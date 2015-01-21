module Worker
       ( ProcessWorker
       , newProcessWorker
       , performProcess
       , runProcessWorker
       ) where

import Control.Applicative
import Control.Monad.STM
import Control.Concurrent
import Control.Exception (SomeException)
import Control.Concurrent.STM.TMVar
import Control.Concurrent.STM.TQueue
import Control.Distributed.Process

data Work = forall a. Work ThreadId (TMVar a) (Process a)

data ProcessWorker = ProcessWorker (TQueue Work)

newProcessWorker :: IO ProcessWorker
newProcessWorker = ProcessWorker <$> newTQueueIO

performProcess :: ProcessWorker -> Process a -> IO a
performProcess (ProcessWorker q) p = do
  t <- myThreadId
  w <- atomically $ do
    w <-newEmptyTMVar
    writeTQueue q $ Work t w p
    return w
  atomically $ takeTMVar w

runProcessWorker :: ProcessWorker -> Process ()
runProcessWorker (ProcessWorker q) = mask $ \restore -> liftIO (atomically $ tryReadTQueue q) >>= \case
  Nothing -> return ()
  Just (Work t w p) -> catch (restore $ p >>= liftIO . atomically . putTMVar w) $ \(e :: SomeException) -> liftIO $ throwTo t e
