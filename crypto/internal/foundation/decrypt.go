package foundation

import "C"

/*
* Provide interface for data encryption.
*/
type Decrypt interface {

    context

    /*
    * Decrypt given data.
    */
    Decrypt (data []byte) ([]byte, error)

    /*
    * Calculate required buffer length to hold the decrypted data.
    */
    DecryptedLen (dataLen uint32) uint32

    /*
    * Release underlying C context.
    */
    Delete ()
}

