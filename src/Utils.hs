{-# OPTIONS_GHC -fno-warn-orphans #-}

module Utils where

import Control.Applicative ((<$>))
import Data.Text (Text)
import Yesod.Core

-- | Convenience function for various "maybe get" things
shouldBe :: (a -> Maybe b) -> (Text -> HandlerT site IO (Maybe a)) -> Text -> HandlerT site IO b
shouldBe t f n = maybeM (invalidArgs [n]) $ ((>>= t) <$> f n)

-- | 'fromMaybe' for monads with convenient signature
maybeM :: Monad m => m a -> m (Maybe a) -> m a
maybeM d m = m >>= maybe d return
