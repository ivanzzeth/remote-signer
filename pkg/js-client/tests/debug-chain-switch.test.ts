/**
 * Debug test for chain switching behavior
 */

// @ts-nocheck
import { describe, it, expect, jest } from '@jest/globals';
import { EIP1193Provider } from '../src';

describe('Debug: Chain Switch Behavior', () => {
  it('should update signer chainId when switching chains', async () => {
    const mockSigner: any = {
      address: '0x1111111111111111111111111111111111111111',
      chainId: '1',
      setChainID: jest.fn(function(newChainId: string) {
        console.log(`[Mock] setChainID called with: ${newChainId}`);
        this.chainId = newChainId;
      }),
      personalSign: jest.fn(async function(message: string) {
        console.log(`[Mock] personalSign called, current chainId: ${this.chainId}`);
        return '0xsignature';
      }),
      signTransaction: jest.fn().mockResolvedValue('0xsignedtx'),
      signTypedData: jest.fn().mockResolvedValue('0xsignature'),
      signHash: jest.fn().mockResolvedValue('0xsignature'),
    };

    console.log('\n=== Creating provider ===');
    const provider = await EIP1193Provider.create({
      signersSource: {
        type: 'manual',
        signers: [mockSigner],
      },
      defaultChainId: 1,
    });

    console.log(`Initial provider.chainId: ${provider.chainId}`);
    console.log(`Initial signer.chainId: ${mockSigner.chainId}`);
    expect(provider.chainId).toBe('0x1');
    expect(mockSigner.chainId).toBe('1');

    console.log('\n=== Switching to Polygon (0x89 = 137) ===');
    await provider.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: '0x89' }],
    });

    console.log(`After switch - provider.chainId: ${provider.chainId}`);
    console.log(`After switch - signer.chainId: ${mockSigner.chainId}`);
    console.log(`setChainID was called ${mockSigner.setChainID.mock.calls.length} times`);
    if (mockSigner.setChainID.mock.calls.length > 0) {
      console.log(`setChainID was called with: ${mockSigner.setChainID.mock.calls[0][0]}`);
    }

    expect(provider.chainId).toBe('0x89');
    expect(mockSigner.setChainID).toHaveBeenCalledWith('137');
    expect(mockSigner.chainId).toBe('137');

    console.log('\n=== Calling personal_sign ===');
    const signature = await provider.request({
      method: 'personal_sign',
      params: ['0x48656c6c6f', '0x1111111111111111111111111111111111111111'],
    });

    console.log(`Signature: ${signature}`);
    console.log(`personalSign was called with signer.chainId: ${mockSigner.chainId}`);

    expect(mockSigner.personalSign).toHaveBeenCalled();
    expect(signature).toBe('0xsignature');

    console.log('\n✅ All checks passed!');
  });

  it('should emit both chainChanged and accountsChanged events', async () => {
    const mockSigner: any = {
      address: '0x1111111111111111111111111111111111111111',
      chainId: '1',
      setChainID: jest.fn(function(newChainId: string) {
        this.chainId = newChainId;
      }),
      personalSign: jest.fn().mockResolvedValue('0xsignature'),
      signTransaction: jest.fn().mockResolvedValue('0xsignedtx'),
      signTypedData: jest.fn().mockResolvedValue('0xsignature'),
      signHash: jest.fn().mockResolvedValue('0xsignature'),
    };

    const provider = await EIP1193Provider.create({
      signersSource: {
        type: 'manual',
        signers: [mockSigner],
      },
      defaultChainId: 1,
    });

    const chainChangedListener = jest.fn();
    const accountsChangedListener = jest.fn();

    provider.on('chainChanged', chainChangedListener);
    provider.on('accountsChanged', accountsChangedListener);

    console.log('\n=== Testing event emission ===');
    await provider.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: '0x89' }],
    });

    console.log(`chainChanged was emitted ${chainChangedListener.mock.calls.length} times`);
    console.log(`accountsChanged was emitted ${accountsChangedListener.mock.calls.length} times`);

    expect(chainChangedListener).toHaveBeenCalledWith('0x89');
    expect(accountsChangedListener).toHaveBeenCalledWith(['0x1111111111111111111111111111111111111111']);

    console.log('✅ Both events were emitted correctly!');
  });
});
