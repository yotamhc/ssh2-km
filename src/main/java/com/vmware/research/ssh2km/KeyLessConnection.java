package com.vmware.research.ssh2km;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

import com.vmware.research.keylib.exceptions.KeyLibException;
import com.vmware.research.keylib.types.IIntegrator;
import com.vmware.research.keylib.types.IPublicKey;
import com.vmware.research.keylib.types.IShareVerifier;
import com.vmware.research.keylib.types.ITicket;
import com.vmware.research.ssh2km.exceptions.InvalidKeyException;

import ch.ethz.ssh2.channel.ChannelManager;

public class KeyLessConnection extends ch.ethz.ssh2.Connection {
	private List<KeyManagerServer> servers;
	private List<IShareVerifier> verifiers;
	private IIntegrator integrator;
	private int numGenerators, minShares;
	private IPublicKey pubKey;
	
	public KeyLessConnection(String hostname, List<KeyManagerServer> servers, List<IShareVerifier> verifiers, IIntegrator integrator, int numGenerators, int minShares, IPublicKey pubKey) {
		super(hostname);
		this.servers = servers;
		this.verifiers = verifiers;
		this.integrator = integrator;
		this.numGenerators = numGenerators;
		this.minShares = minShares;
		this.pubKey = pubKey;
	}
	
	public KeyLessConnection(String hostname, int port, List<KeyManagerServer> servers, List<IShareVerifier> verifiers, IIntegrator integrator, int numGenerators, int minShares, IPublicKey pubKey) {
		super(hostname, port);
		this.servers = servers;
		this.verifiers = verifiers;
		this.integrator = integrator;
		this.numGenerators = numGenerators;
		this.minShares = minShares;
		this.pubKey = pubKey;
	}

	public synchronized boolean authenticateWithPublicKeyThroughKeyManager(String user, ITicket ticket)
			throws IOException, KeyLibException, InvalidKeyException, InterruptedException
	{
		if (tm == null)
			throw new IllegalStateException("Connection is not established!");

		if (authenticated)
			throw new IllegalStateException("Connection is already authenticated!");

		if (am == null)
			am = new KeyLessAuthenticationManager(tm, servers, verifiers, integrator, numGenerators, minShares);
		else
			throw new IllegalStateException("Connection is already authenticated!");

		if (cm == null)
			cm = new ChannelManager(tm);

		if (user == null)
			throw new IllegalArgumentException("user argument is null");

		if (ticket == null)
			throw new IllegalArgumentException("pemPrivateKey argument is null");

		authenticated = ((KeyLessAuthenticationManager)am).authenticateKeyManager(user, ticket, pubKey, getOrCreateSecureRND());
				//authenticatePublicKey(user, pemPrivateKey, password, getOrCreateSecureRND());

		System.out.println("Authentication result: " + authenticated);

		return authenticated;
	}
}
