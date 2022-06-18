import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class IBE {
	//setup阶段，生成pairing相关参数，选取随机数作为系统主密钥，选取随机数g作为群生成元，计算公共参数g^x
	//因此系统公钥为pk=<g,g^x>,选取公共哈希函数H1：{0,1}*->G1*。H2:GT->{0,1}^n
	public static void setup(String pairingParametersFileName,String pkFileName ,String mskFileName) {
		Pairing bp=PairingFactory.getPairing(pairingParametersFileName);
		Element x=bp.getZr().newRandomElement().getImmutable();
		Properties mskProp=new Properties();
		mskProp.setProperty("x", Base64.getEncoder().encodeToString(x.toBytes()));
		storePropToFile(mskProp,mskFileName);
		Element g=bp.getG1().newRandomElement().getImmutable();
		Element gx=g.powZn(x).getImmutable();
		Properties pkProp=new Properties();
		pkProp.setProperty("g", Base64.getEncoder().encodeToString(g.toBytes()));
		pkProp.setProperty("gx", Base64.getEncoder().encodeToString(gx.toBytes()));
		storePropToFile(pkProp,pkFileName);
	}
	//keyGen阶段，给定用户身份ID，将其映射到群GT上，即计算QID=H1(ID)
	//由系统主密钥x计算出此ID对应的私钥sk=Qid^x
	public static void keygen(String pairingParametersFileName,String id,String mskFileName,String skFileName) throws NoSuchAlgorithmException {
		Pairing bp=PairingFactory.getPairing(pairingParametersFileName);
		byte[] idHash=sha1(id);
		Element QID=bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();
		Properties mskProp=loadPropFromFile(mskFileName);
		String xString =mskProp.getProperty("x");
		Element x=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xString)).getImmutable();
		Element sk=QID.powZn(x).getImmutable();
		Properties skProp=new Properties();
		skProp.setProperty("sk", Base64.getEncoder().encodeToString(sk.toBytes()));
		storePropToFile(skProp,skFileName);
	}
	//Encrypt阶段，针对目标用户身份ID属于{0,1}*，计算QID=H1(ID)
	//选取随机数r属于Zr，计算密文组件C1=g^r
	//计算gid=e(QID,g^x)^r
	//计算密文组件C2=M+H2(gid)，其中M属于{0,1}是明文数据
	//最终的密文是<C1,C2>
	public static void encrypt(String pairingParametersFileName,String message,String id,String pkFileName,String ctFileName) throws NoSuchAlgorithmException {
		Pairing bp=PairingFactory.getPairing(pairingParametersFileName);
		byte[] idHash=sha1(id);
		Element QID=bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();
		Properties pkProp=loadPropFromFile(pkFileName);
		String gString=pkProp.getProperty("g");
		Element g=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
		String gxString=pkProp.getProperty("gx");
		Element gx=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gxString)).getImmutable();
		Element r=bp.getZr().newRandomElement().getImmutable();
		Element C1=g.powZn(r).getImmutable();
		Element gID=bp.pairing(QID, gx).powZn(r).getImmutable();
		String qIDString=new String(gID.toBytes());
		byte[] HgID=sha1(qIDString);
		byte[] messageByte=message.getBytes();
		byte[] C2=new byte[messageByte.length];
		for(int i=0;i<messageByte.length;i++) {
			C2[i]=(byte)(messageByte[i]^HgID[i]);
		}
		Properties ctProp=new Properties();
		ctProp.setProperty("C1", Base64.getEncoder().encodeToString(C1.toBytes()));
		ctProp.setProperty("C2", Base64.getEncoder().encodeToString(C2));
		storePropToFile(ctProp, ctFileName);
	}
	//解密的关键在于恢复gid
	//e(sk,C1)=e(Qid^x,g^r)=e(QID,g)^xr=gid
	//恢复明文M=C2+H2(e(sk,C1))
	public static String decrypt(String pairingParametersFileName,String ctFileName,String skFileName) throws NoSuchAlgorithmException {
		Pairing bp=PairingFactory.getPairing(pairingParametersFileName);
		Properties skProp=loadPropFromFile(skFileName);
		String skString=skProp.getProperty("sk");
		Element sk=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(skString)).getImmutable();
		Properties ctProp=loadPropFromFile(ctFileName);
		String C1String=ctProp.getProperty("C1");
		Element C1=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1String)).getImmutable();
		String C2String=ctProp.getProperty("C2");
		byte[] C2=Base64.getDecoder().decode(C2String);
		Element gID=bp.pairing(sk, C1).getImmutable();
		String gIDString=new String(gID.toBytes());
		byte[] HgID=sha1(gIDString);
		byte[] res=new byte[C2.length];
		for(int i=0;i<C2.length;i++) {
			res[i]=(byte)(C2[i]^HgID[i]);
		}
		return new String(res);
	}
	//读取配置文件
	public static Properties loadPropFromFile(String fileName) {
		Properties prop=new Properties();
		try {
			FileInputStream in=new FileInputStream(fileName);
			prop.load(in);
		} catch (IOException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
			System.out.println(fileName+"load failed!");
			System.exit(-1);
		}
		return prop;
	}
	//存储配置文件
	public static void storePropToFile(Properties prop,String fileName) {
		try {
			FileOutputStream out =new FileOutputStream(fileName);
			prop.store(out, null);
		} catch (IOException e) {
			// TODO 自动生成的 catch 块
			e.printStackTrace();
			System.out.println(fileName+"save failed!");
			System.exit(-1);
		}
		
	}
	//使用哈希函数进行哈希
	public static byte[] sha1(String content) throws NoSuchAlgorithmException {
		MessageDigest instance=MessageDigest.getInstance("SHA-1");
		instance.update(content.getBytes());
		return instance.digest();
	}

	public static void main(String[] args) throws NoSuchAlgorithmException {
		// TODO 自动生成的方法存根
		String idBob="bob@qq.com";
		String idAlice="alice@qq.com";
		String message="张国满";
		String pairingParametersFileName="a.properties";
		String pkFileName="pk.properties";
		String mskFileName="msk.properties";
		String skFileName="sk.properties";
		String ctFileName="ct.properties";
		setup(pairingParametersFileName, pkFileName, mskFileName);
		keygen(pairingParametersFileName, idBob, mskFileName, skFileName);
		encrypt(pairingParametersFileName, message, idBob, pkFileName, ctFileName);
		String res=decrypt(pairingParametersFileName, ctFileName, skFileName);
		System.out.println("解密成功："+res);

	}

}
