module Frontend (runFrontend) where

import Control.Monad
import Data.Maybe
import Text.Read (readMaybe)
import Control.Applicative
import Data.Text (Text)
import Control.Monad.Trans.Maybe
import Control.Monad.Trans.Class
import qualified Data.Text as T
import Yesod.Core hiding (Value)
import Yesod.Auth
import qualified Yesod.Auth.Message as Msg
import Yesod.Form
import Yesod.Default.Config as Y
import Yesod.Default.Main
import Database.Esqueleto (Value(..))
import Database.Persist (Entity(..))
import Control.Distributed.Process hiding (Handler, call)
import Control.Distributed.Process.Serializable
import Control.Distributed.Process.Node hiding (newLocalNode)
import Control.Distributed.Process.Backend.SimpleLocalnet
import Control.Distributed.Process.ManagedProcess.Client
import Control.Concurrent.MVar
import Debug.Trace
import Utils
import Calls
import Worker

data App = App { settings :: AppConfig DefaultEnv ()
               , worker :: ProcessWorker
               , authB :: ProcessId
               , packagesB :: ProcessId
               , groupsB :: ProcessId
               }

instance Yesod App where
  approot = ApprootMaster $ appRoot . settings

mkYesod "App" [parseRoutes|
  / HomeR GET
  /auth AuthR Auth getAuth
  /user/me UserMeR GET
  /user/new UserNewR GET POST
  /status StatusR GET
  /packages PackagesR GET
  /packages/#PackageId PackageR GET
  /groups GroupsR GET
  /groups/#GroupId GroupR GET
  /groups/#GroupId/packages GroupPackagesR GET
|]

callBackend :: (RemoteCall name input output) => (App -> ProcessId) -> name -> input -> Handler output
callBackend get name input = do
  app <- getYesod
  liftIO $ performProcess (worker app) $ callR (get app) name input

getUser :: Cookie -> Handler User
getUser uid = fromJust <$> callBackend authB GetUser uid

authRemote :: AuthPlugin App
authRemote =
    AuthPlugin { apName = "remote"
               , apDispatch = dispatch
               , apLogin = \tm -> getLoginR $ tm login
               }
    where
        dispatch "POST" ["login"] = postLoginR >>= sendResponse
        dispatch _ _  = notFound

        login = PluginR "remote" ["login"]

instance YesodAuth App where
  type AuthId App = Cookie
  authPlugins _ = [ authRemote ]
  getAuthId = \c' -> runMaybeT $ do
    c <- MaybeT $ return $ fromPathPiece $ credsIdent c'
    r <- MaybeT $ callBackend authB GetUser c
    return c
  maybeAuthId = (>>= fromPathPiece) <$> lookupSession credsKey

  loginDest _ = HomeR
  logoutDest _ = HomeR

instance RenderMessage App FormMessage where
  renderMessage _ _ = defaultFormMessage

makeApp :: AppConfig DefaultEnv () -> IO App
makeApp settings = do
  discover <- initializeBackend "127.0.0.1" "8000" initRemoteTable
  node <- newLocalNode discover
  peers <- findPeers discover (10^4)
  waitData <- newEmptyMVar
  worker <- newProcessWorker
  void $ forkProcess node $ do
    !auth <- findService peers "auth"
    !packages <- findService peers "packages"
    !groups <- findService peers "groups"
    liftIO $ putMVar waitData (auth, packages, groups)
    forever $ runProcessWorker worker
  (authB, packagesB, groupsB) <- takeMVar waitData

  return App { .. }

runFrontend :: IO ()
runFrontend = defaultMain Y.loadDevelopmentConfig $ makeApp >=> toWaiApp

getHomeR = do
  uid <- runMaybeT $ do
    uid <- MaybeT $ maybeAuthId
    lift $ getUser uid
  defaultLayout
    [whamlet|
      $maybe user <- uid
        <p>You are logged in as #{userName user}
        <p><a href=@{UserMeR}>Profile
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
          check <- callBackend authB CheckUnique n
          return $ if check then Right n else Left ("User already exists!" :: Text)

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
     callBackend authB RegisterUser new
     defaultLayout
       [whamlet|
         <p>Your user has been created.
         <p><a href=@{HomeR}>To the home page
       |]
   _ -> newUser widget enctype

getUserMeR = do
  uid <- requireAuthId
  user <- getUser uid
  defaultLayout
    [whamlet|
      <p>User name: #{userName user}
      <p>User email: #{userEmail user}
    |]

getStatusR = do
  c <- callBackend authB CountUsers ()
  defaultLayout
    [whamlet|
      <p>Total users: #{c}
    |]

getSmthPages :: (RemoteCall name input (ListSmthA a)) =>
                Route App -> (App -> ProcessId) -> name -> (ListSmth -> input) -> (a -> Widget) -> Handler Html
getSmthPages route get name input pitem = do
  let getI d n = fromMaybe d <$> (>>= readMaybe . T.unpack) <$> lookupGetParam n
  start <- getI 0 "start"
  num <- getI 10 "count"
  (n, items) <- callBackend get name (input (start, num))

  defaultLayout
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

getSomePackages route get name input = do
  void requireAuthId
  getSmthPages route get name input (\(Value id, Value name) -> [whamlet|<a href=@{PackageR id}>#{name}|])

getPackagesR = getSomePackages PackagesR packagesB ListPackages id

getPackageR cid = do
  void requireAuthId
  (c, p, gs) <- maybeM notFound $ callBackend packagesB GetPackage cid
  defaultLayout
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
            $forall (Value gi, Value name) <- gs
              <li><a href=@{GroupR gi}>#{name}
    |]

getGroupsR = do
  void requireAuthId
  getSmthPages GroupsR groupsB ListGroups id
    (\(Value id, Value name) -> [whamlet|<a href=@{GroupR id}>#{name}|])

getGroupR cid = do
  void requireAuthId
  c <- maybeM notFound $ callBackend groupsB GetGroup cid
  defaultLayout
    [whamlet|
      <p>Group name: #{groupName c}
      <p>Group description: #{groupDescription c}
      <p><a href=@{GroupPackagesR cid}>Group packages
    |]

getGroupPackagesR i = getSomePackages (GroupPackagesR i) groupsB ListGroupPackages (i, )

postLoginR :: HandlerT Auth (HandlerT App IO) TypedContent
postLoginR = do
  req <- lift $ runInputPost $ (,)
         <$> ireq textField "username"
         <*> ireq passwordField "password"
  lift (callBackend authB AuthUser req) >>= \case
    Nothing -> loginErrorMessageI LoginR Msg.InvalidUsernamePass
    Just (x :: Cookie) -> do
      lift $ setCredsRedirect $ Creds { credsPlugin = "remote"
                                      , credsIdent = traceShowId $ toPathPiece x
                                      , credsExtra = []
                                      }

getLoginR :: Route App -> WidgetT App IO ()
getLoginR loginRoute = do
  [whamlet|
    <form method="post" action="@{loginRoute}">
      <table>
        <tr>
          <th>Username:
          <td>
            <input name="username" required>
        <tr>
          <th>Password:
          <td>
            <input type="password" name="password" required>
        <tr>
          <td>&nbsp;
          <td>
            <button>Login
  |]
