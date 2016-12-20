package com.vmware.research.ssh2km;

import java.io.IOException;
import java.math.BigInteger;

import com.vmware.research.keylib.core.crypto.Dealer;
import com.vmware.research.keylib.types.AbstractShare;
import com.vmware.research.keylib.types.IDealer;
import com.vmware.research.keylib.types.IHashFunction;
import com.vmware.research.keylib.types.IIntegrator;
import com.vmware.research.keylib.types.IMessage;
import com.vmware.research.keylib.types.IPublicKey;
import com.vmware.research.keylib.types.IRandomNumberGenerator;
import com.vmware.research.keylib.types.IShareVerifier;

import ch.ethz.ssh2.crypto.PEMDecoder;
import ch.ethz.ssh2.signature.RSAPrivateKey;

public class SshDealer implements IDealer {

	private Dealer dealer;

	private IHashFunction<IMessage, BigInteger> hash;
	private int keyLength;
	private int numGenerators;
	private int minShares;
	private IRandomNumberGenerator<BigInteger> primesRandom;
	private IRandomNumberGenerator<BigInteger> random;

	public SshDealer(char[] pem, IHashFunction<IMessage, BigInteger> hash, int keyLength, int numGenerators, int minShares,
			IRandomNumberGenerator<BigInteger> primesRandom, IRandomNumberGenerator<BigInteger> random) throws IOException {
		
		Object key = PEMDecoder.decode(pem, null);
		RSAPrivateKey pk = (RSAPrivateKey) key;
		/*
		BigInteger ptqt = findPtQt(pk.getN(), pk.getE(), pk.getD());
		BigInteger delta = BigIntegerMath.factorial(numGenerators);
		BigInteger deltaSqr = delta.multiply(delta);
		BigInteger ep = BigInteger.valueOf(4).multiply(deltaSqr);
		
		BigInteger newD = pk.getD().multiply(deltaSqr.modInverse(ptqt)).mod(pk.getN());
		*/
		this.dealer = new Dealer(hash, keyLength, numGenerators, minShares, primesRandom, random, pk.getN(), pk.getN(), pk.getE(), pk.getD());
	}

	@Override
	public IPublicKey getPublicKey() {
		return dealer.getPublicKey();
	}

	@Override
	public AbstractShare getShare(int id) {
		return dealer.getShare(id);
	}

	@Override
	public IShareVerifier getVerifier(int id) {
		return dealer.getVerifier(id);
	}

	@Override
	public IIntegrator getIntegrator() {
		return dealer.getIntegrator();
	}
	
	public int getMinShares() {
		return minShares;
	}
	
	private static BigInteger findPtQt(BigInteger n, BigInteger e, BigInteger d) {
		
		BigInteger edM1 = e.multiply(d).subtract(BigInteger.ONE);
		BigInteger current = edM1;
		
		BigInteger a = BigInteger.valueOf(2);
		
		while (a.compareTo(e) <= 0) {
			if (current.mod(a).equals(BigInteger.ZERO)) {
				// a divides current
				current = current.divide(a);
			} else {
				a = a.nextProbablePrime();
			}
		}
		
		return current;//.multiply(BigInteger.valueOf(4));
	}
	
}
