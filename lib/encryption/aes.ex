defmodule Encryption.AES do
  @moduledoc """
  Encrypt values with AES in Galois/Counter Mode (GCM)
  https://en.wikipedia.org/wiki/Galois/Counter_Mode
  using a random Initialisation Vector for each encryption,
  this makes "bruteforce" decryption much more difficult.
  See `encrypt/1` and `decrypt/1` for more details.
  """
  @aad "AES256GCM" # Use AES 256 Bit Keys for Encryption.

  @doc """
  Encrypt Using AES Galois/Counter Mode (GCM)
  https://en.wikipedia.org/wiki/Galois/Counter_Mode
  Uses a random IV for each call, and prepends the IV and Tag to the
  ciphertext.  This means that `encrypt/1` will never return the same ciphertext
  for the same value. This makes "cracking" (bruteforce decryption) much harder!
  ## Parameters
  - `plaintext`: Accepts any data type as all values are converted to a String
    using `to_string` before encryption.
  - `key_id`: the index of the AES encryption key used to encrypt the ciphertext
  ## Examples
      iex> Encryption.AES.encrypt("tea") != Encryption.AES.encrypt("tea")
      true
      iex> ciphertext = Encryption.AES.encrypt(123)
      iex> is_binary(ciphertext)
      true
  """
  @spec encrypt(any) :: String.t
  def encrypt(plaintext) do
    iv = :crypto.strong_rand_bytes(16) # create random Initialisation Vector
    key_id = get_latest_key_id()
    key = get_key(key_id) # get the *latest* key in the list of encryption keys
    {ciphertext, tag} =
      :crypto.block_encrypt(:aes_gcm, key, iv, {@aad, to_string(plaintext), 16})
    iv <> tag <> <<key_id::integer-8>> <> ciphertext # "return" iv with the cipher tag & ciphertext
  end

  @doc """
  Decrypt a binary using GCM.
  ## Parameters
  - `ciphertext`: a binary to decrypt, assuming that the first 16 bytes of the
    binary are the IV to use for decryption.
  ## Example
      iex> Encryption.AES.encrypt("test") |> Encryption.AES.decrypt
      "test"
  """
  @spec decrypt(any) :: String.t
  def decrypt(ciphertext) do
    <<iv::binary-16, tag::binary-16, key_id::integer-8, ciphertext::binary>>
      = ciphertext
    :crypto.block_decrypt(:aes_gcm, get_key(key_id), iv, {@aad, ciphertext, tag})
  end

  # @doc """
  # get_latest_key_id - Get latest key ID (index of last key in list of keys)
  # ## Parameters
  # ## Example
  #     iex> Encryption.AES.get_latest_key_id
  #     1
  # """ # doc commented out because https://stackoverflow.com/q/45171024/1148249
  defp get_latest_key_id do
    keys = Application.get_env(:encryption, Encryption.AES)[:keys]
    Enum.count(keys) - 1
  end

  # @doc """
  # get_key - Get encryption key from list of keys.
  # ## Parameters
  # - `key_id`: the index of AES encryption key used to encrypt the ciphertext
  # ## Example
  #     iex> Encryption.AES.get_key
  #     <<13, 217, 61, 143, 87, 215, 35, 162, 183, 151, 179, 205, 37, 148>>
  # """ # doc commented out because https://stackoverflow.com/q/45171024/1148249
  @spec get_key(number) :: String
  defp get_key(key_id) do
    keys = Application.get_env(:encryption, Encryption.AES)[:keys]
    Enum.at(keys, key_id)
  end
end
