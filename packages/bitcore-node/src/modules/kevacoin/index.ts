import { BaseModule } from '..';
import { BTCStateProvider } from '../../providers/chain-state/btc/btc';
import { BitcoinP2PWorker } from './p2p';
import { VerificationPeer } from './VerificationPeer';

export default class KevacoinModule extends BaseModule {
  constructor(services: BaseModule['bitcoreServices']) {
    super(services);
    services.Libs.register('KVA', 'bitcore-lib-kva', 'bitcore-p2p');
    services.P2P.register('KVA', BitcoinP2PWorker);
    services.CSP.registerService('KVA', new BTCStateProvider());
    services.Verification.register('KVA', VerificationPeer);
  }
}
