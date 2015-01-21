module PackageBackend (runPackageBackend) where

import Data.Maybe
import Control.Applicative
import Control.Monad.Trans.Maybe
import Control.Monad.Trans.Class
import Database.Esqueleto
import Control.Distributed.Process.Extras.Time
import Control.Distributed.Process.ManagedProcess hiding (runProcess)
import Calls

runPackageBackend :: IO ()
runPackageBackend = initBackend "8002" "packages" $ \runDB -> do
  runDB $ runMigration migratePackages
  serve () (statelessInit Infinity)
    statelessProcess { apiHandlers =
                          [ handleR_ ListPackages $ getSomethings runDB $ \c  -> return (c ^. PackageId, c ^. PackageName)
                          , handleR_ GetPackage $ \cid -> runDB $ runMaybeT $ do
                               c <- MaybeT $ get cid
                               lift $ do
                                 p <- maybe (return Nothing) (\i -> Just <$> Entity i <$> fromJust <$> get i) $ packageReplacedBy c
                                 gs <- select $ from $ \(gi, g) -> do
                                   where_ $ gi ^. PackageGroupPackage ==. val cid
                                   where_ $ gi ^. PackageGroupGroup ==. g ^. GroupId
                                   return (g ^. GroupId, g ^. GroupName)
                                 return (c, p, gs)
                          ]
                     }
