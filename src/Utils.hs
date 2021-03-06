{-# OPTIONS_GHC -fno-warn-orphans #-}

module Utils where

import Control.Monad
import Control.Applicative ((<$>))
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock
import Data.Aeson
import Yesod.Core
import Network.URL

instance RedirectUrl master URL where
  toTextUrl = return . T.pack . exportURL

instance ToJSON NominalDiffTime where
  toJSON = Number . fromRational . toRational

instance FromJSON NominalDiffTime where
  parseJSON (Number n) = return $ fromRational $ toRational n
  parseJSON _ = mzero

instance ToJSON URL where
  toJSON = String . T.pack . exportURL

instance FromJSON URL where
  parseJSON (String t) = maybeM mzero $ return $ importURL $ T.unpack t
  parseJSON _ = mzero

-- | Convenience function for various "maybe get" things
shouldBe :: (a -> Maybe b) -> (Text -> HandlerT site IO (Maybe a)) -> Text -> HandlerT site IO b
shouldBe t f n = maybeM (invalidArgs [n]) $ ((>>= t) <$> f n)

-- | 'fromMaybe' for monads with convenient signature
maybeM :: Monad m => m a -> m (Maybe a) -> m a
maybeM d m = m >>= maybe d return
