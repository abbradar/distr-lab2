import Control.Monad
import Data.Maybe
import Text.Read (readMaybe)
import Data.Typeable
import Control.Applicative ((<$>), (<*>))
import Data.IORef
import Data.Tuple
import GHC.Generics (Generic)
import Data.Text (Text)
import Control.Monad.Trans.Maybe
import Control.Monad.Trans.Class
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import Data.Time.Clock
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64.URL as B64
import qualified Data.ByteString.Lazy as BL
import Crypto.Random
import Data.Aeson
import qualified Data.Aeson.Types as AT
import qualified Data.Vector as V
import qualified Database.Esqueleto as E
import qualified Database.Esqueleto.Internal.Language as E
import qualified Database.Esqueleto.Internal.Sql as E
import Database.Persist as DB
import Database.Persist.TH
import Database.Persist.Sql
import Yesod.Core
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

data VCS = Git | Hg deriving (Show, Read, Eq)

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
  /user/new UserNewR GET POST
  /status StatusR GET
  /oauth OAuthR GET POST
  /oauth/reply OAuthReplyR POST
  /clients ClientsR GET
  /clients/new ClientNewR POST
  !/clients/#ClientId ClientR GET
  /packages PackagesR GET
  !/packages/#PackageId PackageR GET
  /groups GroupsR GET
  !/groups/#GroupId GroupR GET
  /groups/#GroupId/packages GroupPackagesR GET
|]

data OAuthToken = OAuthToken { tokenUntil :: UTCTime
                             , tokenClient :: ClientId
                             , tokenUser :: UserId
                             }
                deriving (Generic)

instance ToJSON OAuthToken
instance FromJSON OAuthToken

instance YesodAuth App where
  type AuthId App = UserId
  authPlugins _ = [ authHashDB $ Just . UniqueUser ]
  getAuthId = getAuthIdHashDB AuthR $ Just . UniqueUser

  loginDest _ = HomeR
  logoutDest _ = HomeR

-- | Like 'requireAuthId', but also accepts OAuth2 authentification.
requireAnyAuthId :: Handler UserId
requireAnyAuthId = runMaybeT (msum $ map MaybeT [ maybeAuthId
                                              , maybeOAuthId
                                              ])
                   >>= maybeM (permissionDenied "Not authorized")

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
  liftIO $ decodeUtf8 <$> CS.encryptIO (csKey app) (B.concat $ BL.toChunks $ encode obj)

decryptJSON :: FromJSON a => Text -> Handler (Maybe a)
decryptJSON t = do
  app <- getYesod
  return $ CS.decrypt (csKey app) (encodeUtf8 t) >>= decodeStrict

maybeOAuthId :: Handler (Maybe UserId)
maybeOAuthId = runMaybeT $ do
  auth <- MaybeT $ lookupHeader "Authorization"
  let (t, T.strip -> access) = T.breakOn " " $ decodeUtf8 auth
  guard $ t == "bearer"
  lift $ do
    OAuthToken { .. } <- decryptJSON access >>= maybeM (oauthError "invalid_request")
    good <- all (/= 0) <$> runDB (sequence [ count [UserId ==. tokenUser]
                                           , count [ClientId ==. tokenClient]
                                           ])
    now <- liftIO getCurrentTime
    unless (good && now <= tokenUntil) $ oauthError "invalid_client"
    return tokenUser

makeApp :: AppConfig DefaultEnv () -> IO App
makeApp settings = do
  dbConf <- withYamlEnvironment "config/postgresql.yml" (appEnv settings) DB.loadConfig >>= DB.applyEnv
  appPool <- createPoolConfig dbConf
  runSqlPool (runMigration migrateAll) appPool
  entropy <- createEntropyPool
  randGen <- newIORef $ cprgCreate entropy
  csKey <- liftIO $ CS.getKey keyFile

  return App { .. }

main :: IO ()
main = defaultMain Y.loadDevelopmentConfig (makeApp >=> toWaiApp)

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
          clients <- runDB $ count [ UserName ==. n]
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

getUserMeR = do
  uid <- requireAnyAuthId
  Just user <- runDB $ get uid
  defaultLayoutJson
    [whamlet|
      <p>User name: #{userName user}
      <p>User email: #{userEmail user}
    |]
    $ return $ object [ "name" .= userName user
                      , "email" .= userEmail user
                      ]

getStatusR = do
  c <- runDB $ count ([] :: [Filter User])
  defaultLayoutJson
    [whamlet|
      <p>Total users: #{c}
    |]
    $ return $ object [ "total_users" .= c ]

getSomethings :: (E.From E.SqlQuery E.SqlExpr E.SqlBackend a1, E.SqlSelect a2 a) =>
                 Route App -> (a1 -> E.SqlQuery a2) -> (Widget -> Handler Html) -> (a -> Widget) -> (a -> [AT.Pair]) -> Handler TypedContent
getSomethings route query layout pitem jitem = do
  let getI d n = fromMaybe d <$> (>>= readMaybe . T.unpack) <$> lookupGetParam n
  start <- getI 0 "start"
  count <- getI 10 "count"
  items' <- runDB $ E.select $ E.from $ \u -> do
    E.limit $ fromIntegral $ count + 1
    E.offset $ fromIntegral start
    query u
  let items = take count items'
  selectRep $ do
    provideRep $ do
      layout [whamlet|
              <ul>
                $forall e <- items
                  <li>^{pitem e}
                $if start /= 0
                  <p><a href="@{route}?start=0&count=#{count}">First page
                $if length items' > count
                  <p><a href="@{route}?start=#{start + count}&count=#{count}">Next page
                $if start /= 0
                  <p><a href="@{route}?start=#{min 0 (start - count)}&count=#{count}">Previous page
             |]
    provideRep $ return $ Array $ V.fromList $ map (object . jitem) items

getClientsR = do
  uid <- requireAuthId
  getSomethings ClientsR (\x -> E.where_ (x E.^. ClientUser E.==. E.val uid) >> return x)
    (\w -> defaultLayout
           [whamlet|
             <form method=post action=@{ClientNewR}>
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

postClientNewR = do
  clientUser <- requireAuthId
  app <- getYesod
  clientKey <- decodeUtf8 <$> B64.encode <$> liftIO (atomicModifyIORef (randGen app) $ swap . cprgGenerate 16)
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
    gs <- E.select $ E.from $ \(gi, g) -> do
      E.where_ (gi E.^. PackageGroupPackage E.==. E.val cid)
      E.where_ (gi E.^. PackageGroupGroup E.==. g E.^. GroupId)
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
                      \p -> E.from $ \gi -> do
                        E.where_ (gi E.^. PackageGroupGroup E.==. E.val i)
                        E.where_ (gi E.^. PackageGroupPackage E.==. p E.^. PackageId)
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

data OAuthCode = OAuthCode URL OAuthToken
               deriving (Generic)

instance ToJSON OAuthCode
instance FromJSON OAuthCode

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
  cid <- getCid >>= maybeM (reqError "invalid_request")
  Entity reqClient _ <- runDB (getBy $ UniqueClient cid) >>=
                        maybeM (reqError "unauthorized_client")
  void requireAuthId
  reqState <- lookupGetParam "state"
  (widget, enctype) <- generateFormPost $ allowForm $ Just OAuthRequest { .. }
  defaultLayout
    [whamlet|
      <form method=post action=@{OAuthReplyR} enctype=#{enctype}>
        ^{widget}
        <button>Proceed
    |]

postOAuthReplyR = do
  tokenUser <- requireAuthId
  ((FormSuccess (answer, OAuthRequest { .. }), _), _) <- runFormPost $ allowForm Nothing
  void $ if answer
    then do
      app <- getYesod
      tokenUntil <- addUTCTime (30 * 60) <$> liftIO getCurrentTime
      code <- encryptJSON $ OAuthCode reqURL OAuthToken { tokenClient = reqClient
                                                          , .. }
      redirect $ foldl add_param reqURL $ [("code", T.unpack code)]
        ++ maybe [] (\s -> [("state", T.unpack s)]) reqState
    else redirect $ add_param reqURL ("error", "access_denied")

postOAuthR = do
  let getCode = runMaybeT $ do
        rtype <- MaybeT $ lookupPostParam "grant_type"
        guard $ rtype == "authorization_code"
        code <- MaybeT (lookupPostParam "code") >>= MaybeT . decryptJSON
        url <- MaybeT $ (>>= importURL . T.unpack) <$> lookupPostParam "redirect_uri"
        cid <- MaybeT $ lookupPostParam "client_id"
        Entity client _ <- MaybeT $ runDB $ getBy $ UniqueClient cid
        return (code, client, url)
  (OAuthCode turl token@OAuthToken { .. }, client, url) <- getCode >>= maybeM (oauthError "invalid_request")
  now <- liftIO getCurrentTime
  unless (turl == url && tokenClient == client && now < tokenUntil) $ oauthError "invalid_client"
  access <- encryptJSON token
  return $ object [ "token_type" .= ("bearer" :: Text)
                  , "access_token" .= access
                  , "expires_in" .= (tokenUntil `diffUTCTime` now)
                  ]
