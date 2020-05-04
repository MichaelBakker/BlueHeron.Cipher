Imports System
Imports System.Text
Imports System.Security.Cryptography
Imports System.IO
Imports System.Linq

Public Class StringCipher

	' This constant is used to determine the keysize of the encryption algorithm in bits.
	' Divide this by 8 to get the equivalent number of bytes.
	Private Const Keysize As Integer = 256
	' This constant determines the number of iterations for the password bytes generation function.
	Private Const DerivationIterations As Integer = 1000

	Public Shared Function Encrypt(plainText, passPhrase) As String
		' Salt And IV Is randomly generated each time, but is preprended to encrypted cipher text, so that the same Salt And IV values can be used when decrypting.  
		var saltStringBytes = Generate256BitsOfRandomEntropy();
			var ivStringBytes = Generate256BitsOfRandomEntropy();
			var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
			Using (var password = New Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
				Using (var symmetricKey = New RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    Using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes))
                    {
                        Using (var memoryStream = New MemoryStream())
                        {
                            Using (var cryptoStream = New CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                            {
                                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                                cryptoStream.FlushFinalBlock();
                                // Create the final bytes as a concatenation of the random salt bytes, the random iv bytes And the cipher bytes.
                                var cipherTextBytes = saltStringBytes;
								cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
                                cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
                                memoryStream.Close();
                                cryptoStream.Close();
                                Return Convert.ToBase64String(cipherTextBytes);
                            }
                        }
                    }
                }
            }
        End Function

	Public Static String Decrypt(String cipherText, String passPhrase)
        {
            // Get the complete stream of bytes that represent:
            // [32 bytes of Salt] + [32 bytes of IV] + [n bytes of CipherText]
            var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);
            // Get the saltbytes by extracting the first 32 bytes from the supplied cipherText bytes.
            var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(Keysize / 8).ToArray();
            // Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
            var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(Keysize / 8).Take(Keysize / 8).ToArray();
            // Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
            var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip((Keysize / 8) * 2).Take(cipherTextBytesWithSaltAndIv.Length - ((Keysize / 8) * 2)).ToArray();

            Using (var password = New Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                Using (var symmetricKey = New RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    Using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
                    {
                        Using (var memoryStream = New MemoryStream(cipherTextBytes))
                        {
                            Using (var cryptoStream = New CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            {
                                var plainTextBytes = New Byte[cipherTextBytes.Length];
                                var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                memoryStream.Close();
                                cryptoStream.Close();
                                Return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                            }
                        }
                    }
                }
            }
        }

        Private Shared Function Generate256BitsOfRandomEntropy() As Byte()
		Dim randomBytes(31) As Byte ' 32 Bytes will give us 256 bits

		Using rngCsp As New RNGCryptoServiceProvider()
			' fill the array with cryptographically secure random bytes
			rngCsp.GetBytes(randomBytes)
		End Using

		Return randomBytes

	End Function

End Class