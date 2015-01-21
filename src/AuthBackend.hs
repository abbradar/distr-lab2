module AuthBackend (runAuthBackend) where

import Data.Maybe
import Database.Persist
import Database.Persist.Sql
import Yesod.Auth.HashDB (HashDBUser(..), setPassword, validatePass)
import Control.Distributed.Process.Extras.Time
import Control.Distributed.Process.ManagedProcess hiding (runProcess)
import Calls

instance HashDBUser User where
  userPasswordHash = Just . userPassword
  setPasswordHash h u = u { userPassword = h }

runAuthBackend :: IO ()
runAuthBackend = initBackend "8001" "auth" $ \runDB -> do
  runDB $ runMigration migrateUser
  serve () (statelessInit Infinity)
    statelessProcess { apiHandlers =
                          [ handleR_ CheckUnique $ \login -> do
                               clients <- runDB $ count [UserName ==. login]
                               return $ clients == 0
                          , handleR_ GetUser $ \cookie -> runDB (get cookie)
                          , handleR_ AuthUser $ \(login, pwd) -> runDB (getBy $ UniqueUser login) >>= \case
                               Just (Entity (id :: Cookie) u) | fromJust (validatePass u pwd) -> return $ Just id
                               _ -> return Nothing
                          , handleR_ RegisterUser $ \new -> do
                               user <- setPassword (userPassword new) new
                               runDB $ insert_ user
                               return ()
                          , handleR_ CountUsers $ \() -> runDB (count ([] :: [Filter User]))
                          ] 
                     }
