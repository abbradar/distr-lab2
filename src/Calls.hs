{-# LANGUAGE UndecidableInstances #-}

module Calls where

import Text.Read (readMaybe)
import Control.Applicative
import Data.Monoid
import Data.Typeable
import Data.Binary
import Data.Maybe
import Control.Monad
import GHC.Generics (Generic)
import Control.Monad.IO.Class
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8', encodeUtf8)
import qualified Database.Persist as D
import Database.Persist.TH
import Database.Esqueleto hiding (get)
import qualified Database.Esqueleto.Internal.Sql as E
import qualified Database.Esqueleto.Internal.Language as E
import Control.Distributed.Process hiding (call)
import Control.Distributed.Process.Node hiding (newLocalNode)
import Control.Distributed.Process.Backend.SimpleLocalnet
import Control.Distributed.Process.ManagedProcess hiding (runProcess)
import Control.Distributed.Process.Serializable
import Control.Distributed.Process.Extras.SystemLog
import Database.Persist.Postgresql (PostgresConf)
import qualified Yesod.Default.Config as Y

data AuthType = Cookie | OAuth
              deriving (Show, Eq, Ord)

type Login = Text
type Password = Text

instance Binary Text where
  put = put . encodeUtf8
  get = (decodeUtf8' <$> get) >>= \case
    Right t -> return t
    Left e -> fail $ show e

instance (Show (Key a), Read (Key a)) => Binary (Key a) where
  put = put . show
  get = (readMaybe <$> get) >>= \case
    Just x -> return x
    Nothing -> fail "Cannot decode Key"

deriving instance Typeable Key

share [mkPersist sqlSettings, mkMigrate "migrateUser"] [persistLowerCase|
  User
    name Login
    password Password
    email Text
    UniqueUser name
    deriving Show Generic Typeable
|]

type Cookie = UserId
instance Binary User

deriving instance Typeable Entity

deriving instance Generic (Value a)
instance Binary a => Binary (Value a)

instance (PersistEntity a, Binary a) => Binary (Entity a) where
  put (Entity key val) = put key >> put val
  get = Entity <$> get <*> get

share [mkPersist sqlSettings, mkMigrate "migratePackages"] [persistLowerCase|
  Package
    name Text
    description Text
    url Text
    replacedBy PackageId Maybe
    UniquePackage name
    deriving Show Generic Typeable

  Group
    name Text
    description Text
    UniqueGroup name
    deriving Show Generic Typeable

  PackageGroup
    package PackageId
    group GroupId
    UniquePG package group
    deriving Show Generic Typeable
|]

instance Binary Package
instance Binary Group

data RemoteCallS name input = RemoteCallS name input deriving (Show, Generic, Typeable)
instance (Binary name, Binary input) => Binary (RemoteCallS name input)

class (Show name, Show input, Serializable name, Serializable input, Serializable output) =>
      RemoteCall name input output | name -> input output where

  callR :: ProcessId -> name -> input -> Process output
  callR pid name input = call pid $ RemoteCallS name input

  handleR_ :: name -> (input -> Process output) -> Dispatcher s
  handleR_ _ handler = handleCall_ $ \(RemoteCallS (n :: name) input) -> do
    debug logChannel $ "Received: " ++ show n ++ " " ++ show input
    handler input

data CheckUnique = CheckUnique deriving (Show, Generic, Typeable)
instance Binary CheckUnique
instance RemoteCall CheckUnique Login Bool where

data RegisterUser = RegisterUser deriving (Show, Generic, Typeable)
instance Binary RegisterUser
instance RemoteCall RegisterUser User () where

data AuthUser = AuthUser deriving (Show, Generic, Typeable)
instance Binary AuthUser
instance RemoteCall AuthUser (Login, Password) (Maybe Cookie) where

data GetUser = GetUser deriving (Show, Generic, Typeable)
instance Binary GetUser
instance RemoteCall GetUser Cookie (Maybe User) where

data CountUsers = CountUsers deriving (Show, Generic, Typeable)
instance Binary CountUsers
instance RemoteCall CountUsers () Int where

type Offset = Int
type Limit = Int

type ListSmth = (Offset, Limit)
type ListSmthA a = (Int, [a])

type PackageEntry = (Value PackageId, Value Text)
type GroupEntry = (Value GroupId, Value Text)

data ListPackages = ListPackages deriving (Show, Generic, Typeable)
instance Binary ListPackages
instance RemoteCall ListPackages ListSmth (ListSmthA PackageEntry) where

data GetPackage = GetPackage deriving (Show, Generic, Typeable)
instance Binary GetPackage
instance RemoteCall GetPackage PackageId (Maybe (Package, Maybe (Entity Package), [GroupEntry])) where

data ListGroups = ListGroups deriving (Show, Generic, Typeable)
instance Binary ListGroups
instance RemoteCall ListGroups ListSmth (ListSmthA GroupEntry) where

data GetGroup = GetGroup deriving (Show, Generic, Typeable)
instance Binary GetGroup
instance RemoteCall GetGroup GroupId (Maybe Group) where

data ListGroupPackages = ListGroupPackages deriving (Show, Generic, Typeable)
instance Binary ListGroupPackages
instance RemoteCall ListGroupPackages (GroupId, ListSmth) (ListSmthA PackageEntry) where

findService :: [NodeId] -> String -> Process ProcessId
findService peers name = do
  mapM_ (\p -> whereisRemoteAsync p name) peers
  r <- liftM catMaybes $ forM peers $ const $ do
    WhereIsReply _ t <- expect
    return t
  case r of
   [] -> liftIO (putStrLn $ "can't find '" ++ name ++ "', trying again...") >> findService peers name
   (h:_) -> return h

reply_ :: (Monoid s, Serializable r) => r -> Process (ProcessReply r s)
reply_ = flip reply mempty

stdinLog :: LogLevel -> LogFormat -> Process ProcessId
stdinLog = systemLog (liftIO . putStrLn) (return ())

type RunDB = forall a. SqlPersistT IO a -> Process a

initBackend :: String -> String -> (RunDB -> Process ()) -> IO ()
initBackend port name pr = do
  (dbConf :: PostgresConf) <- Y.withYamlEnvironment "config/postgresql.yml" Y.Development D.loadConfig >>= D.applyEnv
  appPool <- D.createPoolConfig dbConf
  discover <- initializeBackend "127.0.0.1" port initRemoteTable
  node <- newLocalNode discover
  runProcess node $ do
    void $ stdinLog Debug return
    getSelfPid >>= register name
    pr $ \x -> liftIO $ runSqlPool x appPool

getSomethings' :: ( PersistEntity a1
                  , PersistEntityBackend a1 ~ SqlBackend
                  , E.SqlSelect a2 a3
                  ) => RunDB -> (a -> ListSmth) -> (a -> SqlExpr (Entity a1) -> SqlQuery a2) -> (a -> Process (ListSmthA a3))
getSomethings' runDB conv query i = do
  let (start, num) = conv i
  runDB $ do
    items <- select $ from $ \u -> do
      offset $ fromIntegral start
      limit $ fromIntegral num
      query i u
    [Value n] <- select $ from $ \n -> query i n >> return countRows
    return (n, items)

getSomethings ::  ( PersistEntity a1
                  , PersistEntityBackend a1 ~ SqlBackend
                  , E.SqlSelect a2 a3
                  ) => RunDB -> (SqlExpr (Entity a1) -> SqlQuery a2) -> (ListSmth -> Process (ListSmthA a3))
getSomethings appPool = getSomethings' appPool id . const
