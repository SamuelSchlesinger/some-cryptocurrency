{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
module Main where

import qualified GHC.Generics
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PSS as DigitalSignature
import qualified Data.Binary as Binary
import qualified Crypto.Hash.Algorithms as Hash
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import qualified Crypto.Random as Random

-- Blockchain.hs
newtype Blockchain = Blockchain { unBlockchain :: Vector (Signed Hash.SHA512 Block) }
  Blockchain (Signed Hash.SHA512 Block) Blockchain
  | Genesis Block
  deriving (Binary.Binary, GHC.Generics.Generic)

data Block = Block
  { issuer :: PublicKey
  , nonce :: BS.ByteString
  , transactions :: [Signed Hash.SHA512 Transaction] }
  deriving (Binary.Binary, GHC.Generics.Generic)

data Transaction = Transaction
  { txFrom :: PublicKey
  , txTo :: PublicKey
  , txSource :: (Integer, Integer) 
  -- unspent transaction output source: (block, transaction)
  , txAmount :: Integer }
  deriving (Binary.Binary, GHC.Generics.Generic)

-- Signed.hs
data Signed hash a = Signed
  { signed :: a
  , signature :: BS.ByteString
  , signee :: PublicKey }
  deriving (Binary.Binary, GHC.Generics.Generic)

sign :: (Binary.Binary v, Random.MonadRandom m)
  => PrivateKey
  -> v
  -> m (Either RSA.Error (Signed Hash.SHA512 v))
sign privateKey v = do
  eitherSig <- DigitalSignature.sign Nothing (DigitalSignature.defaultPSSParams Hash.SHA512) (cryptonitePrivateKey privateKey) (LBS.toStrict $ Binary.encode v)
  pure (Signed v <$> eitherSig <*> pure (publicKey privateKey))

verify :: Binary.Binary v 
  => Signed Hash.SHA512 v
  -> Bool
verify (Signed a s x) = DigitalSignature.verify (DigitalSignature.defaultPSSParams Hash.SHA512) (cryptonitePublicKey x) (LBS.toStrict $ Binary.encode a) s

-- AsymmetricEncryption.hs
newtype PrivateKey = PrivateKey { cryptonitePrivateKey :: RSA.PrivateKey }

publicKey :: PrivateKey -> PublicKey
publicKey (PrivateKey RSA.PrivateKey{private_pub}) = PublicKey private_pub

instance Binary.Binary PrivateKey where
  put (PrivateKey RSA.PrivateKey{..}) = do
    Binary.put (PublicKey private_pub)
    Binary.put private_d
    Binary.put private_p
    Binary.put private_q
    Binary.put private_dP
    Binary.put private_dQ
    Binary.put private_qinv
  get = PrivateKey <$> (RSA.PrivateKey <$> (cryptonitePublicKey <$> Binary.get) <*> Binary.get <*> Binary.get <*> Binary.get <*> Binary.get <*> Binary.get <*> Binary.get)

newtype PublicKey = PublicKey { cryptonitePublicKey :: RSA.PublicKey }

instance Binary.Binary PublicKey where
  put (PublicKey RSA.PublicKey{..}) = do
    Binary.put public_size
    Binary.put public_n
    Binary.put public_e
  get = PublicKey <$> (RSA.PublicKey <$> Binary.get <*> Binary.get <*> Binary.get)

-- Main.hs
main :: IO ()
main = putStrLn "Hello, Haskell!"
