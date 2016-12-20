package com.vmware.research.ssh2km;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import com.google.common.math.BigIntegerMath;
import com.vmware.research.keylib.core.MessageFactory;
import com.vmware.research.keylib.core.hash.HashFunctionFactory;
import com.vmware.research.keylib.exceptions.KeyLibException;
import com.vmware.research.keylib.types.AbstractShare;
import com.vmware.research.keylib.types.IHashFunction;
import com.vmware.research.keylib.types.IIntegrator;
import com.vmware.research.keylib.types.IKey;
import com.vmware.research.keylib.types.IMessage;
import com.vmware.research.keylib.types.IPublicKey;
import com.vmware.research.keylib.types.IShareVerifier;
import com.vmware.research.keylib.types.ITicket;
import com.vmware.research.ssh2km.exceptions.InvalidKeyException;

import ch.ethz.ssh2.auth.AuthenticationManager;
import ch.ethz.ssh2.crypto.digest.SHA1;
import ch.ethz.ssh2.packets.PacketUserauthFailure;
import ch.ethz.ssh2.packets.PacketUserauthRequestPublicKey;
import ch.ethz.ssh2.packets.Packets;
import ch.ethz.ssh2.packets.TypesWriter;
import ch.ethz.ssh2.signature.RSAPublicKey;
import ch.ethz.ssh2.signature.RSASHA1Verify;
import ch.ethz.ssh2.signature.RSASignature;
import ch.ethz.ssh2.transport.TransportManager;

public class KeyLessAuthenticationManager extends AuthenticationManager {

	private List<KeyManagerServer> servers;
	private List<IShareVerifier> verifiers; 
	private IIntegrator integrator;
	private int numGenerators, minShares;
	
	public KeyLessAuthenticationManager(TransportManager tm, List<KeyManagerServer> servers, List<IShareVerifier> verifiers, IIntegrator integrator, int numGenerators, int minShares) {
		super(tm);
		this.servers = servers;
		this.verifiers = verifiers;
		this.integrator = integrator;
		this.numGenerators = numGenerators;
		this.minShares = minShares;
	}
	
	public boolean authenticateKeyManager(String user, ITicket ticket, IPublicKey pubKey, SecureRandom rnd)
			throws InterruptedException, IOException, InvalidKeyException, KeyLibException
	{
		try
		{
			initialize(user);

			if (methodPossible("publickey") == false)
				throw new IOException("Authentication method publickey not supported by the server at this stage.");

			List<AbstractShare> signedShares = new ArrayList<>();
			
			// Prepare data for signing
			// Translate public key to ganymed-ssh-2 type
			RSAPublicKey pubkeyssh = new RSAPublicKey(pubKey.getExponent(), pubKey.getModulus());
			
			byte[] pk_enc = RSASHA1Verify.encodeSSHRSAPublicKey(pubkeyssh);

			TypesWriter tw = new TypesWriter();
			{
				byte[] H = tm.getSessionIdentifier();

				tw.writeString(H, 0, H.length);
				tw.writeByte(Packets.SSH_MSG_USERAUTH_REQUEST);
				tw.writeString(user);
				tw.writeString("ssh-connection");
				tw.writeString("publickey");
				tw.writeBoolean(true);
				tw.writeString("ssh-rsa");
				tw.writeString(pk_enc, 0, pk_enc.length);
			}

			byte[] msg1 = tw.getBytes();
			IMessage msg = generateMessage(msg1, ticket, pubKey);

			IHashFunction<IMessage, BigInteger> hash = HashFunctionFactory.getInstance().createIdentityHashFunction();
			
			// Request signatures
			for (int i = 0; i < servers.size(); i++) {
				KeyManagerServer server = servers.get(i);
				IShareVerifier verifier = verifiers.get(i);
				
				final int serverID = i;
				Consumer<AbstractShare> cons = new Consumer<AbstractShare>() {
					
					@Override
					public void accept(AbstractShare t) {
						synchronized (signedShares) {
							try {
								if (verifier.verify(t, msg, hash)) {
									// Share is verified, collect it
									signedShares.add(t);
								} else {
									throw new KeyLibException("");
								}
							} catch (KeyLibException e) {
								System.err.printf("Received invalid response from server %d. Ignoring...\n", serverID);
							}
						}
					}
				};
				server.sign(msg, cons);
			}
			
			// Wait for at least minShares valid responses
			while (signedShares.size() < minShares) {
				// Wait
				Thread.sleep(100);
			}
			
			List<AbstractShare> sharesForIntegrator;
			synchronized (signedShares) {
				sharesForIntegrator = signedShares.subList(0, minShares);
			}
			
			IKey srsasig = integrator.integrate(msg, sharesForIntegrator);
			
			//BigInteger delta = BigIntegerMath.factorial(numGenerators);
			//BigInteger ep = BigInteger.valueOf(4).multiply(delta).multiply(delta);
			
			BigInteger rsasig = srsasig.getKey();
			
			
			//Object key = PEMDecoder.decode(PEMPrivateKey, password);
			//RSAPrivateKey pk = (RSAPrivateKey) key;

			
			RSASignature ds = new RSASignature(rsasig); // RSASHA1Verify.generateSignature(msg1, pk);
			
			boolean verifySig = RSASHA1Verify.verifySignature(msg1, ds, pubkeyssh);
			
			if (!verifySig) {
				System.err.println("KM produced wrong RSA signature");
				return false;
			}

			byte[] rsa_sig_enc = RSASHA1Verify.encodeSSHRSASignature(ds);

			PacketUserauthRequestPublicKey ua = new PacketUserauthRequestPublicKey("ssh-connection", user,
					"ssh-rsa", pk_enc, rsa_sig_enc);
			tm.sendMessage(ua.getPayload());

			byte[] ar = getNextMessage();

			if (ar[0] == Packets.SSH_MSG_USERAUTH_SUCCESS)
			{
				authenticated = true;
				tm.removeMessageHandler(this, 0, 255);
				return true;
			}

			if (ar[0] == Packets.SSH_MSG_USERAUTH_FAILURE)
			{
				PacketUserauthFailure puf = new PacketUserauthFailure(ar, 0, ar.length);

				remainingMethods = puf.getAuthThatCanContinue();
				isPartialSuccess = puf.isPartialSuccess();

				return false;
			}

			throw new IOException("Unexpected SSH message (type " + ar[0] + ")");

		}
		catch (IOException e)
		{
			tm.close(e, false);
			throw (IOException) new IOException("Publickey authentication failed.").initCause(e);
		}
	}
	
	private static IMessage generateMessage(byte[] message, ITicket ticket, IPublicKey pk) throws IOException {
		SHA1 md = new SHA1();
		md.update(message);
		byte[] sha_message = new byte[md.getDigestLength()];
		md.digest(sha_message);

		byte[] der_header = new byte[] { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
				0x04, 0x14 };

		int rsa_block_len = (pk.getModulus().bitLength() + 7) / 8;

		int num_pad = rsa_block_len - (2 + der_header.length + sha_message.length) - 1;

		if (num_pad < 8)
			throw new IOException("Cannot sign with RSA, message too long");

		byte[] sig = new byte[der_header.length + sha_message.length + 2 + num_pad];

		sig[0] = 0x01;

		for (int i = 0; i < num_pad; i++)
		{
			sig[i + 1] = (byte) 0xff;
		}

		sig[num_pad + 1] = 0x00;

		System.arraycopy(der_header, 0, sig, 2 + num_pad, der_header.length);
		System.arraycopy(sha_message, 0, sig, 2 + num_pad + der_header.length, sha_message.length);

		return MessageFactory.getInstance().fromBytes(ticket, sig);
	}

}
