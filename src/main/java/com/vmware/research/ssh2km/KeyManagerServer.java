package com.vmware.research.ssh2km;

import java.util.function.Consumer;

import com.vmware.research.keylib.types.AbstractShare;
import com.vmware.research.keylib.types.IMessage;
import com.vmware.research.keylib.types.ISigner;

public class KeyManagerServer {
	
	private ISigner localSigner;
	
	public KeyManagerServer(ISigner localSigner) {
		this.localSigner = localSigner;
	}
	
	public void sign(IMessage msg, Consumer<AbstractShare> callback) {
		AbstractShare share = localSigner.sign(msg);
		callback.accept(share);
	}
	
}
