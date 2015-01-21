module GroupBackend (runGroupBackend) where

import Database.Esqueleto
import Control.Distributed.Process.Extras.Time
import Control.Distributed.Process.ManagedProcess hiding (runProcess)
import Calls

runGroupBackend :: IO ()
runGroupBackend = initBackend "8003" "groups" $ \runDB -> do
  runDB $ runMigration migratePackages
  serve () (statelessInit Infinity)
    statelessProcess { apiHandlers =
                          [ handleR_ ListGroups $ getSomethings runDB $ \c -> return (c ^. GroupId, c ^. GroupName)
                          , handleR_ GetGroup $ \cid -> runDB $ get cid
                          , handleR_ ListGroupPackages $ getSomethings' runDB snd $
                            \(gid, _) p -> from $ \gi -> do
                              where_ $ gi ^. PackageGroupGroup ==. val gid
                              where_ $ gi ^. PackageGroupPackage ==. p ^. PackageId
                              return (p ^. PackageId, p ^. PackageName)
                          ]
                     , unhandledMessagePolicy = Log
                     }
