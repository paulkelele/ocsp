package root;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

enum RefUrl {
	OCSP(0), ISSUER_CERTIFICATE(1);
	private final int ref;

	private RefUrl(int ref) {
		this.ref = ref;
	}
	public int getValue() {
		return ref;
	}
}

class ArgsException extends Exception {
	private static final long serialVersionUID = 1L;

	public ArgsException(String message) {
		super(message);
	}
}

class OCSPUrlException extends Exception {
	private static final long serialVersionUID = 1L;

	public OCSPUrlException() {
		super("cannot get ocsp url or issuer certificate from this certificate");
	}
}

/**
 * Verify a X.509 certificate status with OCSP Used library: Bouncy Castle
 * version 1.71 necessary library in classpath: bcpkix-jdk18on-171.jar
 * bcprov-jdk18on-171.jar bcutil-jdk18on-171.jar
 * 
 * @author stef
 *
 */
public class Main {

	public static void main(String[] args) throws Throwable {
		try {
			if (args.length == 0) {
				throw new ArgsException("no certificate file as argument.");
			}
		} catch (ArgsException e) {
			System.out.println(e.getMessage());
			System.exit(1);
		}
		System.out.println("..............Verify status certificate X.509 with OCSP...............");
		File cc = new File(System.getProperty("user.dir"), args[0]);

		Security.setProperty("crypto.policy", "unlimited");
		Security.addProvider(new BouncyCastleProvider());
		InputStream is = null;
		try {
			is = new FileInputStream(cc);
		} catch (FileNotFoundException e) {
			System.out.println(e.getMessage());
			System.exit(1);
		}
		X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);

		/* read ocsp server url path and issuer certificate url path from certificate */
		String ocspURL = null;
		String issuerCertificateURL = null;
		try {
			List<String> urlList = getAuthorityInformationAccessOcspUrls(certificate);
			if (urlList.size() != 2)
				throw new OCSPUrlException();
			ocspURL = urlList.get(RefUrl.OCSP.getValue());
			issuerCertificateURL = urlList.get(RefUrl.ISSUER_CERTIFICATE.getValue());
		} catch (OCSPUrlException e) {
			System.out.println(e.getMessage());
			System.exit(1);
		}
		InputStream issuerCertificateStream = null;
		X509Certificate issuerCertificate = null;
		try {
			issuerCertificateStream = new URL(issuerCertificateURL).openStream();
			issuerCertificate = (X509Certificate) CertificateFactory.getInstance("X.509")
					.generateCertificate(issuerCertificateStream);
		} catch (IOException e) {
			System.out.println(e.getMessage());
			System.out.println("program stop....");
			System.exit(1);

		} catch (CertificateException e) {
			System.out.println("impossible to parse the issuer certificate");
			System.out.println("program stop....");
			System.exit(1);
			// TODO: handle exception
		}

		// create id from certificate we wante to verify status
		JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
		DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();
		DigestCalculator digestCalculator = digestCalculatorProvider.get(CertificateID.HASH_SHA1);
		CertificateID certId = new CertificateID(digestCalculator,
				new X509CertificateHolder(issuerCertificate.getEncoded()), certificate.getSerialNumber());

		// create nonce to avoid replay attack
		BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
		Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
				new DEROctetString(nonce.toByteArray()));

		// basic request generation with nonce
		OCSPReqBuilder requestBuilder = new OCSPReqBuilder();
		OCSPReq ocspReq = requestBuilder.setRequestExtensions(new Extensions(new Extension[] { ext }))
				.addRequest(certId).build();

		byte[] data = ocspReq.getEncoded();
		HttpURLConnection con = null;
		try {
			con = (HttpURLConnection) new URL(ocspURL).openConnection();
			con.setDoOutput(true);
			con.setDoInput(true);
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-type", "application/ocsp-request");
			con.setRequestProperty("Accept", "application/ocsp-response");
			con.setRequestProperty("Content-length", String.valueOf(data.length));
			OutputStream out = con.getOutputStream();
			out.write(data);
			out.flush();
			InputStream i = (InputStream) con.getContent();
			byte[] response = i.readAllBytes();
			System.out.println("response size: [" + response.length + "] bytes");

			OCSPResp ocspresp = new OCSPResp(response);
			int responseStatus = ocspresp.getStatus();

			if (responseStatus == OCSPResponseStatus.SUCCESSFUL) {
				System.out.println("ocsp server status : SUCCESSFUL");
				BasicOCSPResp basicResponse = (BasicOCSPResp) ocspresp.getResponseObject();
				SingleResp[] singleResp = basicResponse.getResponses();
				if (singleResp.length != 1)
					throw new Exception("response lenght is anormal");
				Object status = singleResp[0].getCertStatus();
				SingleResp sr = singleResp[0];
				sr.getCertStatus();
				if (status == null || status == CertificateStatus.GOOD) {
					System.out.println("Certificat: GOOD");
				} else if (status instanceof org.bouncycastle.cert.ocsp.RevokedStatus) {
					System.out.println("certificat: REVOKED");
				} else {
					System.out.println("certificat: UNKNOWN");
				}
			} else if (responseStatus == OCSPResponseStatus.INTERNAL_ERROR) {
				System.out.println("ocsp server status : INTERNAL_ERROR");
				System.err.println("cannot check certificate status");
				System.exit(1);
			} else if (responseStatus == OCSPResponseStatus.MALFORMED_REQUEST) {
				System.out.println("ocsp server status : MALFORMED_REQUEST");
				System.err.println("cannot check certificate status");
				System.exit(1);
			} else if (responseStatus == OCSPResponseStatus.UNAUTHORIZED) {
				System.out.println("ocsp server status : UNAUTHORIZED");
				System.err.println("cannot check certificate status");
				System.exit(1);
			} else if (responseStatus == OCSPResponseStatus.SIG_REQUIRED) {
				System.out.println("ocsp server status : SIG_REQUIRED");
				System.err.println("cannot check certificate status");
				System.exit(1);
			} else if (responseStatus == OCSPResponseStatus.TRY_LATER) {
				System.out.println("ocsp server status : TRY_LATER");
				System.err.println("cannot check certificate status");
				System.exit(1);
			} else {
				System.out.println("ocsp server status : UNKNOWN");
				System.err.println("cannot check certificate status");
				System.exit(1);
			}

		} catch (UnknownHostException uhe) {
			System.out.println("ocsp server at adress [" + uhe.getMessage() + "] is unknown");
			System.exit(1);
		} catch (Exception e) {
			System.out.println("Error: " + e.getMessage());
			System.exit(1);
		} finally {
			if (con != null) {
				con.disconnect();
			}
		}
	}

	public static List<String> getAuthorityInformationAccessOcspUrls(X509Certificate x509Certificate)
			throws OCSPUrlException {
		List<String> ocspUrlList = new ArrayList<>();

		ASN1InputStream extensionAns1InputStream = null;
		ASN1InputStream octetAns1InputStream = null;
		try {
			byte[] extBytes = x509Certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
			extensionAns1InputStream = new ASN1InputStream(extBytes);
			ASN1OctetString ans1OctetString = (ASN1OctetString) extensionAns1InputStream.readObject();
			byte[] octetsBytes = ans1OctetString.getOctets();
			octetAns1InputStream = new ASN1InputStream(octetsBytes);
			ASN1Encodable ans1Encodable = octetAns1InputStream.readObject();
			AuthorityInformationAccess auth = AuthorityInformationAccess.getInstance(ans1Encodable);
			AccessDescription[] accessDescriptionArray = auth.getAccessDescriptions();
			GeneralName generalName;
			String url;
			for (AccessDescription accessDescription : accessDescriptionArray) {
				generalName = accessDescription.getAccessLocation();
				url = generalName.toString();
				if (url.length() > 3) {
					ocspUrlList.add(url.substring(3));
				}
			}
		} catch (IOException e) {
			System.out.println(e.getMessage());
			throw new OCSPUrlException();
		} finally {
			if (extensionAns1InputStream != null) {
				try {
					extensionAns1InputStream.close();
				} catch (IOException e) {
					System.out.println("Error closing stream: " + e.getMessage());
				}
			}
			if (octetAns1InputStream != null) {
				try {
					octetAns1InputStream.close();
				} catch (IOException e) {
					System.out.println("Error closing stream: " + e.getMessage());
				}
			}
		}

		return ocspUrlList;
	}

}
