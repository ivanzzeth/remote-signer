// Package evm — signer_handler.go currently serves as a routing container.
// All signer endpoint logic has been split into:
//   - signer_crud.go    (listSigners, createSigner, handleDeleteSigner, handlePatchSignerLabels, signerIsHDDerivedNonPrimary)
//   - signer_locking.go (handleUnlock, handleLock, handleApproveSigner, handleTransferOwnership)
//   - signer_access.go  (handleGrantAccess, handleRevokeAccess, handleListAccess)
//   - signer_wallet.go  (listWallets, listWalletSigners, signerInfoByAddress)
package evm
