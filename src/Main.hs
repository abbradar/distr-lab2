import Control.Monad
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
import qualified Database.Esqueleto as E
import Database.Persist as DB
import Database.Persist.TH
import Database.Persist.Sql
import Yesod.Core
import Yesod.Auth
import Yesod.Persist (YesodPersist(..), get404, defaultRunDB)
import Yesod.Paginate
import Yesod.Form
import Yesod.Default.Config as Y
import Yesod.Default.Main
import qualified Network.HTTP.Types as H
import Yesod.Auth.HashDB (HashDBUser(..), authHashDB, getAuthIdHashDB, setPassword)
import Database.Persist.Postgresql (PostgresConf)
import qualified Web.ClientSession as CS
import Network.URL

data App = App { dbConf :: PostgresConf
               , appPool :: ConnectionPool
               , settings :: AppConfig DefaultEnv ()
               , csKey :: CS.Key
               , randGen :: IORef SystemRNG
               }

instance RedirectUrl master URL where
  toTextUrl = return . T.pack . exportURL

instance ToJSON NominalDiffTime where
  toJSON = Number . fromRational . toRational

instance FromJSON NominalDiffTime where
  parseJSON (Number n) = return $ fromRational $ toRational n
  parseJSON _ = mzero

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
|]

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
  /clients/page/#Int ClientsPageR GET
  /clients/new ClientNewR POST
  !/clients/#ClientId ClientR GET
|]

instance ToJSON URL where
  toJSON = String . T.pack . exportURL

instance FromJSON URL where
  parseJSON (String t) = maybeM mzero $ importURL $ T.unpack t
  parseJSON _ = mzero

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

-- | Convenience function for various "maybe get" things
shouldBe :: (a -> Maybe b) -> (Text -> Handler (Maybe a)) -> Text -> Handler b
shouldBe t f n = ((>>= t) <$> f n) >>= maybeM (invalidArgs [n])

-- | 'fromMaybe', lifted for monadic actions.
maybeM :: Monad m => m a -> Maybe a -> m a
maybeM d = maybe d return

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
      $nothing
        <p>You are not logged in
        <p><a href=@{AuthR LoginR}>Login
        <p><a href=@{UserNewR}>Register
      <p><a href=@{StatusR}>Status
    |]

newUserForm = renderDivs $ User
    <$> areq (checkM unique textField) "Name" Nothing
    <*> areq textField "Password" Nothing
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

getClientsPageR i = do
  uid <- requireAuthId
  (items :: Page (Route App) (Entity Client)) <-
    paginateWith PageConfig { pageSize = 10
                            , currentPage = i
                            , firstPageRoute = ClientsR
                            , pageRoute = ClientsPageR
                            } $ \i -> do
      E.where_ (i E.^. ClientUser E.==. E.val uid)
      return i

  defaultLayout
    [whamlet|
      <form method=post action=@{ClientNewR}>
        <button>New client
      <ul>
        $forall Entity id client <- pageResults items
          <li><a href=@{ClientR id}>#{clientKey client}
      $maybe fp <- firstPage items
        <p><a href=@{fp}>First page
      $maybe fp <- nextPage items
        <p><a href=@{fp}>Next page
      $maybe fp <- previousPage items
        <p><a href=@{fp}>Previous page
    |]

getClientsR = getClientsPageR 1

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
