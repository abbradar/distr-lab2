import Control.Monad
import Data.Maybe
import Text.Read (readMaybe)
import Data.Typeable
import Data.Monoid
import Control.Applicative
import Data.IORef
import Data.Tuple
import GHC.Generics (Generic)
import Data.Text (Text)
import Control.Monad.Trans.Maybe
import Control.Monad.Trans.Class
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import Data.Time.Clock
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64'
import qualified Data.ByteString.Base64.URL as B64
import qualified Data.ByteString.Lazy as BL
import Crypto.Random
import Data.Aeson hiding (Value)
import qualified Data.Aeson.Types as AT
import qualified Data.Vector as V
import Database.Esqueleto
import qualified Database.Esqueleto.Internal.Language as E
import qualified Database.Esqueleto.Internal.Sql as E
import qualified Database.Persist as D
import qualified Database.Persist.Sql as D
import Database.Persist.TH
import Yesod.Core hiding (Value)
import Yesod.Auth
import Yesod.Persist (YesodPersist(..), get404, defaultRunDB)
import Yesod.Form
import Yesod.Default.Config as Y
import Yesod.Default.Main
import qualified Network.HTTP.Types as H
import Yesod.Auth.HashDB (HashDBUser(..), authHashDB, getAuthIdHashDB, setPassword)
import Database.Persist.Postgresql (PostgresConf)
import qualified Web.ClientSession as CS
import Network.URL
import Utils

share [mkPersist sqlSettings, mkMigrate "migrateAll"] [persistLowerCase|
  User
    name Text
    password Text
    email Text
    UniqueUser name
    deriving (Typeable)

  Client
    key Text
    user UserId
    UniqueClient key

  Token json
    client ClientId
    user UserId
    until UTCTime
    code Text
    UniqueToken code

  Package
    name Text
    description Text
    url Text
    replacedBy PackageId Maybe
    UniquePackage name

  Group
    name Text
    description Text

  PackageGroup
    package PackageId
    group GroupId
    UniquePG package group
|]

data App = App { dbConf :: PostgresConf
               , appPool :: ConnectionPool
               , settings :: AppConfig DefaultEnv ()
               , csKey :: CS.Key
               , randGen :: IORef SystemRNG
               }

instance HashDBUser User where
  userPasswordHash = Just . userPassword
  setPasswordHash h u = u { userPassword = h }

keyFile :: String
keyFile = "client_session_key.aes"

instance Yesod App where
  approot = ApprootMaster $ appRoot . settings
  makeSessionBackend _ = fmap Just $ defaultClientSessionBackend minutes keyFile
    where minutes = 2 * 60

mkYesod "App" [parseRoutes|
  / HomeR GET
  /auth AuthR Auth getAuth
  /user/me UserMeR GET
  /user/me/cleartokens UserClearTokensR POST
  /user/new UserNewR GET POST
  /status StatusR GET
  /oauth OAuthR GET POST
  /oauth/reply OAuthReplyR POST
  /clients ClientsR GET
  !/clients/new ClientNewR POST
  /clients/#ClientId ClientR GET
  /packages PackagesR GET
  /packages/#PackageId PackageR GET
  /groups GroupsR GET
  /groups/#GroupId GroupR GET
  /groups/#GroupId/packages GroupPackagesR GET
|]

instance YesodAuth App where
  type AuthId App = UserId
  authPlugins _ = [ authHashDB $ Just . UniqueUser ]
  getAuthId = getAuthIdHashDB AuthR $ Just . UniqueUser

  loginDest _ = HomeR
  logoutDest _ = HomeR

-- | Like 'requireAuthId', but also accepts OAuth2 authentification.
requireAnyAuthId :: Handler UserId
requireAnyAuthId = maybeM (permissionDenied "Not authorized") $
                   runMaybeT (msum $ map MaybeT [ maybeAuthId
                                              , maybeOAuthId
                                              ])

instance YesodPersist App where
  type YesodPersistBackend App = SqlBackend
  runDB = defaultRunDB dbConf appPool

instance YesodAuthPersist App

instance RenderMessage App FormMessage where
  renderMessage _ _ = defaultFormMessage

oauthError :: Text -> Handler a
oauthError e = sendResponseStatus H.badRequest400 $ object [ "error" .= e ]

encryptJSON :: ToJSON a => a -> Handler Text
encryptJSON obj = do
  app <- getYesod
  liftIO $ decodeUtf8 <$> B64.encode <$> B64'.decodeLenient <$> CS.encryptIO (csKey app) (B.concat $ BL.toChunks $ encode obj)

decryptJSON :: FromJSON a => Text -> Handler (Maybe a)
decryptJSON t = do
  app <- getYesod
  return $ CS.decrypt (csKey app) (B64'.encode $ B64.decodeLenient $ encodeUtf8 t) >>= decodeStrict

maybeOAuthId :: Handler (Maybe UserId)
maybeOAuthId = runMaybeT $ do
  (t, T.strip -> access) <- T.breakOn " " <$> decodeUtf8 <$> MaybeT (lookupHeader "Authorization")
  guard $ t == "bearer"
  lift $ do
    OAuthAccess id <- maybeM (oauthError "invalid_request") $ decryptJSON access
    maybeM (oauthError "invalid_client") $ runMaybeT $ do
      Token {..} <- MaybeT $ runDB $ get id
      now <- liftIO getCurrentTime
      guard $ now < tokenUntil
      return tokenUser

makeApp :: AppConfig DefaultEnv () -> IO App
makeApp settings = do
  dbConf <- withYamlEnvironment "config/postgresql.yml" (appEnv settings) D.loadConfig >>= D.applyEnv
  appPool <- createPoolConfig dbConf
  runSqlPool (runMigration migrateAll) appPool
  entropy <- createEntropyPool
  randGen <- newIORef $ cprgCreate entropy
  csKey <- liftIO $ CS.getKey keyFile

  return App { .. }

main :: IO ()
main = defaultMain Y.loadDevelopmentConfig $ makeApp >=> toWaiApp

getHomeR = do
  maid <- maybeAuth
  defaultLayout
    [whamlet|
      $maybe (Entity _ user) <- maid
        <p>You are logged in as #{userName user}
        <p><a href=@{UserMeR}>Profile
        <p><a href=@{ClientsR}>Clients
        <p><a href=@{AuthR LogoutR}>Logout
        <p><a href=@{PackagesR}>Packages
        <p><a href=@{GroupsR}>Groups
      $nothing
        <p>You are not logged in
        <p><a href=@{AuthR LoginR}>Login
        <p><a href=@{UserNewR}>Register
      <p><a href=@{StatusR}>Status
    |]

newUserForm = renderDivs $ User
    <$> areq (checkM unique textField) "Name" Nothing
    <*> areq passwordField "Password" Nothing
    <*> areq emailField "E-Mail" Nothing
  where unique n = do
          clients <- runDB $ D.count [UserName D.==. n]
          return $ if clients /= 0 then Left ("User already exists!" :: Text) else Right n 

newUser widget enctype = do
  defaultLayout
    [whamlet|
      <form method=post action=@{UserNewR} enctype=#{enctype}>
        ^{widget}
        <button>Submit
    |]

getUserNewR = generateFormPost newUserForm >>= uncurry newUser

postUserNewR = do
  ((result, widget), enctype) <- runFormPost newUserForm
  case result of
   FormSuccess new -> do
     user <- setPassword (userPassword new) new
     runDB $ insert_ user
     defaultLayout
       [whamlet|
         <p>Your user has been created.
         <p><a href=@{HomeR}>To the home page
       |]
   _ -> newUser widget enctype

-- We use this to apply CSRF protection
emptyForm = renderDivs $ pure ()

getUserMeR = do
  uid <- requireAnyAuthId
  Just user <- runDB $ get uid
  (widget, enctype) <- generateFormPost emptyForm
  defaultLayoutJson
    [whamlet|
      <p>User name: #{userName user}
      <p>User email: #{userEmail user}
      <p><form method=post action=@{UserClearTokensR} enctype=#{enctype}>
        ^{widget}
        <button>Clear access tokens
    |]
    $ return $ object [ "name" .= userName user
                      , "email" .= userEmail user
                      ]

postUserClearTokensR = do
  uid <- requireAuthId
  ((FormSuccess (), _), _) <- runFormPost emptyForm
  runDB $ D.deleteWhere [TokenUser D.==. uid]
  defaultLayout
    [whamlet|
      <p>Your tokens have been cleared.
      <p><a href=@{UserMeR}>Return to my user page
    |]

getStatusR = do
  c <- runDB $ D.count ([] :: [D.Filter User])
  defaultLayoutJson
    [whamlet|
      <p>Total users: #{c}
    |]
    $ return $ object [ "total_users" .= c ]

getSomethings route query layout pitem jitem = do
  let getI d n = fromMaybe d <$> (>>= readMaybe . T.unpack) <$> lookupGetParam n
  start <- getI 0 "start"
  num <- getI 10 "count"
  (items, n :: Int) <- runDB $ do
    items <- select $ from $ \u -> do
      offset $ fromIntegral start
      limit $ fromIntegral num
      query u
    [Value n] <- select $ from $ \n -> query n >> return countRows
    return (items, n)

  selectRep $ do
    provideRep $ layout
      [whamlet|
        <p>Total items: #{n}
        <ul>
          $forall e <- items
            <li>^{pitem e}
        $if n >= (start + num)
          <p><a href="@{route}?start=#{start + num}&count=#{num}">Next page
        $if start /= 0
          <p><a href="@{route}?start=#{min 0 (start - num)}&count=#{num}">Previous page
          <p><a href="@{route}?start=0&count=#{num}">First page
      |]
    provideRep $ return $ object [ "total" .= n
                                 , "items" .= map (object . jitem) items
                                 ]

getClientsR = do
  uid <- requireAuthId
  (widget, enctype) <- generateFormPost emptyForm
  getSomethings ClientsR (\x -> where_ (x ^. ClientUser ==. val uid) >> return x)
    (\w -> defaultLayout
           [whamlet|
             <form method=post action=@{ClientNewR} enctype=#{enctype}>
               ^{widget}
               <button>New client
             ^{w}
           |])
    (\(Entity id client) -> [whamlet|<a href=@{ClientR id}>#{clientKey client}|])
    (const [])

getClientR cid = do
  uid <- requireAuthId
  c <- runDB $ get404 cid
  unless (clientUser c == uid) $ permissionDenied "You don't own this client entry"
  defaultLayout $ do
    [whamlet|
      <p>Client ID: #{clientKey c}
    |]

randomA :: Int -> Handler ByteString
randomA n = do
  app <- getYesod
  liftIO $ atomicModifyIORef (randGen app) $ swap . cprgGenerate n

postClientNewR = do
  clientUser <- requireAuthId
  ((FormSuccess (), _), _) <- runFormPost emptyForm
  clientKey <- decodeUtf8 <$> B64.encode <$> randomA 16
  cid <- runDB $ insert Client { .. }
  defaultLayout
    [whamlet|
      <p>Your client has been created.
      <p><a href=@{ClientR cid}>To the new client
    |]

getSomePackages r f = do
  void requireAnyAuthId
  getSomethings r f defaultLayout
    (\(Entity id pkg) -> [whamlet|<a href=@{PackageR id}>#{packageName pkg}|])
    (\(Entity id pkg) -> [ "id" .= id
                         , "name" .= packageName pkg
                         ])

getPackagesR = getSomePackages PackagesR return

getPackageR :: PackageId -> Handler TypedContent
getPackageR cid = do
  void requireAnyAuthId
  (c, p, gs) <- runDB $ do
    c <- get404 cid
    p <- maybe (return Nothing) (\i -> Just <$> Entity i <$> fromJust <$> get i) $ packageReplacedBy c
    gs <- select $ from $ \(gi, g) -> do
      where_ $ gi ^. PackageGroupPackage ==. val cid
      where_ $ gi ^. PackageGroupGroup ==. g ^. GroupId
      return g
    return (c, p, gs)
  defaultLayoutJson
    [whamlet|
      <p>Package name: #{packageName c}
      <p>Package URL: #{packageUrl c}
      $maybe Entity ri rp <- p
        <p>Replaced by:
          <a href=@{PackageR ri}>#{packageName rp}
      <p>Package description: #{packageDescription c}
      $if not $ null gs
        <p>Package in groups:
          <ul>
            $forall Entity gi g <- gs
              <li><a href=@{GroupR gi}>#{groupName g}
    |]
    $ return $ object $ [ "name" .= packageName c
                        , "url" .= packageUrl c
                        , "description" .= packageDescription c
                        , ("groups", Array $ V.fromList $ map
                                     (\(Entity gi g) -> object [ "id" .= gi
                                                              , "name" .= groupName g
                                                              ]) gs)
                        ] ++ maybe [] (\x -> [ "replaced_by" .= x ]) (packageReplacedBy c)

getGroupsR = do
  void requireAnyAuthId
  getSomethings GroupsR return defaultLayout
    (\(Entity id g) -> [whamlet|<a href=@{GroupR id}>#{groupName g}|])
    (\(Entity id g) -> [ "id" .= id
                       , "name" .= groupName g
                       ])

getGroupR cid = do
  void requireAnyAuthId
  c <- runDB $ get404 cid
  defaultLayoutJson
    [whamlet|
      <p>Group name: #{groupName c}
      <p>Group description: #{groupDescription c}
      <p><a href=@{GroupPackagesR cid}>Group packages
    |]
    $ return $ object $ [ "name" .= groupName c
                        , "description" .= groupDescription c
                        ]

getGroupPackagesR i = getSomePackages (GroupPackagesR i) $
                      \p -> from $ \gi -> do
                        where_ $ gi ^. PackageGroupGroup ==. val i
                        where_ $ gi ^. PackageGroupPackage ==. p ^. PackageId
                        return p

data OAuthRequest = OAuthRequest { reqClient :: ClientId
                                 , reqURL :: URL
                                 , reqState :: Maybe Text
                                 }
                    deriving (Generic)

instance ToJSON OAuthRequest
instance FromJSON OAuthRequest

instance PathPiece OAuthRequest where
  fromPathPiece = decodeStrict . B64.decodeLenient . encodeUtf8
  toPathPiece = decodeUtf8 . B64.encode . B.concat . BL.toChunks . encode

allowForm r = renderDivs $ (,)
              <$> areq checkBoxField "Allow access for this client" (Just False)
              <*> areq hiddenField "" r

getOAuthR = do
  let checkURL t = importURL (T.unpack t) >>= \case
        u@(URL (Absolute _) _ _) -> Just u
        _ -> Nothing
      getCid = runMaybeT $ do
        rtype <- MaybeT $ lookupGetParam "response_type"
        guard $ rtype == "code"
        MaybeT $ lookupGetParam "client_id"
  reqURL <- shouldBe checkURL lookupGetParam "redirect_uri"
  let reqError :: String -> Handler a
      reqError t = redirect $ add_param reqURL ("error", t)
  cid <- maybeM (reqError "invalid_request") $ getCid
  Entity reqClient _ <- maybeM (reqError "unauthorized_client") $
                        runDB $ getBy $ UniqueClient cid
  void requireAuthId
  reqState <- lookupGetParam "state"
  (widget, enctype) <- generateFormPost $ allowForm $ Just OAuthRequest { .. }
  defaultLayout
    [whamlet|
      <form method=post action=@{OAuthReplyR} enctype=#{enctype}>
        ^{widget}
        <button>Proceed
    |]

data OAuthCode = OAuthCode { codeURL :: URL
                           , codeId :: TokenId
                           }
               deriving (Generic)

instance ToJSON OAuthCode
instance FromJSON OAuthCode

data OAuthAccess = OAuthAccess { accessId :: TokenId }
               deriving (Generic)

instance ToJSON OAuthAccess
instance FromJSON OAuthAccess

data OAuthRefresh = OAuthRefresh { refreshId :: TokenId }
                  deriving (Generic)

instance ToJSON OAuthRefresh
instance FromJSON OAuthRefresh

postOAuthReplyR = do
  tokenUser <- requireAuthId
  ((FormSuccess (answer, OAuthRequest { .. }), _), _) <- runFormPost $ allowForm Nothing
  void $ if answer
    then do
      tokenUntil <- addUTCTime (10 * 60) <$> liftIO getCurrentTime
      tokenCode <- decodeUtf8 <$> B64.encode <$> randomA 16
      id <- runDB $ insert Token { tokenClient = reqClient
                                 , ..
                                 }
      code <- encryptJSON $ OAuthCode reqURL id
      redirect $ foldl add_param reqURL $ [("code", T.unpack code)]
        ++ maybe [] (\s -> [("state", T.unpack s)]) reqState
    else redirect $ add_param reqURL ("error", "access_denied")

postOAuthR = maybeM (oauthError "invalid_request") $ runMaybeT $ do
  now <- liftIO getCurrentTime
  let expireTime = addUTCTime (30 * 60) now
  id <- MaybeT (lookupPostParam "grant_type") >>= \case
    "authorization_code" -> do
      code <- MaybeT $ lookupPostParam "code"
      OAuthCode turl tid <- MaybeT $ decryptJSON code
      url <- MaybeT $ (>>= importURL . T.unpack) <$> lookupPostParam "redirect_uri"
      cid <- MaybeT $ lookupPostParam "client_id"
      Entity client _ <- MaybeT $ runDB $ getBy $ UniqueClient cid
      lift $ maybeM (oauthError "invalid_client") $ runDB $ get tid >>= \case
        Nothing -> D.deleteWhere [TokenCode D.==. code] >> return Nothing
        Just Token {..} | turl == url && tokenClient == client && now < tokenUntil -> do
                            D.delete tid
                            Just <$> insert Token { tokenUntil = expireTime
                                                  , ..
                                                  }
                        | otherwise -> return Nothing

    "refresh_token" -> do
      refresh <- MaybeT $ lookupPostParam "refresh_token"
      liftIO $ putStrLn $ T.unpack refresh
      OAuthRefresh id <- MaybeT $ decryptJSON refresh
      lift $ do
        maybeM (oauthError "invalid_client") $ runDB $ runMaybeT $ do
          Token {..} <- MaybeT $ get id
          lift $ do
            D.delete id
            insert Token { tokenUntil = expireTime
                         , ..
                         }

    _ -> mzero

  lift $ do
    access <- encryptJSON $ OAuthAccess id
    refresh <- encryptJSON $ OAuthRefresh id
    liftIO $ putStrLn $ T.unpack refresh
    return $ object [ "token_type" .= ("bearer" :: Text)
                    , "access_token" .= access
                    , "refresh_token" .= refresh
                    , "expires_in" .= (expireTime `diffUTCTime` now)
                    ]
