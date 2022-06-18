import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class FIBE {
	//生成pair相关参数<e,g,G1,GT,Zr>
	//确定属性全集U的整数集合{1,2，……，U}，以及系统门限值
	//针对每个属性i选择随机数ti属于Zr作为主密钥组件，计算Ti=g^ti作为对应的公钥组件
	//选取随机数y属于Zr，并计算Y=e(g,g)^y
	//系统主密钥msk为<t1,t2,……,tu,y>,公钥pk为<T1,T2,……,Tu,Y>
	public static void setup(String pairingParametersFileName,int U,int d,String pkFileName,String mskFileName) {
		Pairing bp=PairingFactory.getPairing(pairingParametersFileName);
		//选定生成元
		Element g=bp.getG1().newRandomElement().getImmutable();
		//生成配置文件
		Properties mskProp=new Properties();
		Properties pkProp=new Properties();
		//为每个属性选取一个属于Zr的随机数，并计算主密钥组件和公钥组件
		for(int i=1;i<=U;i++) {
			Element t=bp.getZr().newRandomElement().getImmutable();
			Element T=g.powZn(t).getImmutable();
			//将计算得到的密钥组件值保存到配置文件中
			mskProp.setProperty("t"+i, Base64.getEncoder().withoutPadding().encodeToString(t.toBytes()));
			pkProp.setProperty("T"+i, Base64.getEncoder().withoutPadding().encodeToString(T.toBytes()));
			
		}
		//随机选取一个随机数y
		Element y=bp.getZr().newRandomElement().getImmutable();
		//计算Y=e(g,g)^y
		Element egg_y=bp.pairing(g, g).powZn(y).getImmutable();
		mskProp.setProperty("y", Base64.getEncoder().withoutPadding().encodeToString(y.toBytes()));
		pkProp.setProperty("egg_y", Base64.getEncoder().withoutPadding().encodeToString(egg_y.toBytes()));
		pkProp.setProperty("g", Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));
		
		pkProp.setProperty("d", Integer.toString(d));
		storePropToFile(mskProp,mskFileName);
		storePropToFile(pkProp,pkFileName);
		
	}
	//随机选择一个d-1次多项式q(x)，使得q(0)=y
	//针对用户属性集合s中的每个属性i，计算q(i),进一步算出Di=g^q(i)/ti
	//用户私钥sk={Di},i属于s
	public static void keygen(String pairingParametersFileName,int[] userAttList,String pkFileName,String mskFileName,String skFileName) throws NoSuchAlgorithmException{
		Pairing bp=PairingFactory.getPairing(pairingParametersFileName);
		Properties pkProp=loadPropFromFile(pkFileName);
		//得到存储到配置文件中的生成元和门限值
		String gString=pkProp.getProperty("g");
		Element g=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
		String dString=pkProp.getProperty("d");
		int d=Integer.parseInt(dString);
		
		Properties mskProp=loadPropFromFile(mskFileName);
		//从配置文件中得到选取的随机数y
		String yString=mskProp.getProperty("y");
		Element y=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(yString)).getImmutable();
		
		
		Element[] coef=new Element[d];
		coef[0]=y;
		for(int i=1;i<d;i++) {
			//为随机多项式选取随机系数
			coef[i]=bp.getZr().newRandomElement().getImmutable();
		}
		//创建配置文件
		Properties skProp=new Properties();
		
		for(int att:userAttList) {
			//得到相应的属性值
			String tString=mskProp.getProperty("t"+att);
			Element t=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(tString)).getImmutable();
			//针对用户属性集合s中的每个属性i，计算q(i),q(i)=coef[i]*i^i，i从0到d-1相加
			Element q=qx(bp.getZr().newElement(att),coef,bp.getZr()).getImmutable();
			//利用q(i)计算得到Di=g^（q(i)/ti）
			Element D=g.powZn(q.div(t)).getImmutable();
			//将用户私钥sk={Di},i属于用户属性集合，保存到配置文件中
			skProp.setProperty("D"+att, Base64.getEncoder().withoutPadding().encodeToString(D.toBytes()));
			
		}
		//将用户属性列表写入存储到配置文件
		skProp.setProperty("userAttList", Arrays.toString(userAttList));
		//保存配置文件
		storePropToFile(skProp, skFileName);
		
	}
	//选取随机数s属于Zr，针对明文消息M属于GT，计算E1=M*Y^s=M*e(g,g)^ys
	//针对明文属性集合w中的每个属性i，计算Ei=Ti^s
	//密文为ct=<E1,{Ei}i属于w>
	public static void encrypt(String pairingParametersFileName,Element message,int[] messageAttList,String pkFileName,String ctFileName) {
		Pairing bp=PairingFactory.getPairing(pairingParametersFileName);
		//读取创建配置文件
		Properties pkProp=loadPropFromFile(pkFileName);
		//得到Y=e(g,g)^y的值
		String eggString=pkProp.getProperty("egg_y");
		Element egg_y=bp.getGT().newElementFromBytes(Base64.getDecoder().decode(eggString)).getImmutable();
		//选取随机数s属于Zr
		Element s=bp.getZr().newRandomElement().getImmutable();
		//计算第一部分密钥E1=M*Y^s=M*e(g,g)^ys
		Element EP=message.duplicate().mul(egg_y.powZn(s)).getImmutable();
		//创建配置文件
		Properties ctProp=new Properties();
		//针对明文属性集合w中的每个属性i，计算Ei=Ti^s，其中Ti=g^ti
		for(int att:messageAttList) {
			//从配置文件中提取Ti的值
			String TString=pkProp.getProperty("T"+att);
			Element T=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TString)).getImmutable();
			//计算Ei的值
			Element E=T.powZn(s).getImmutable();
			//将第二部分密文Ei的值写入配置文件中
			ctProp.setProperty("E"+att, Base64.getEncoder().withoutPadding().encodeToString(E.toBytes()));
			
			
		}
		//将第一部分密文和明文属性列表写入配置文件
		ctProp.setProperty("EP", Base64.getEncoder().withoutPadding().encodeToString(EP.toBytes()));
		ctProp.setProperty("messageAttList", Arrays.toString(messageAttList));
		//保存配置文件
		storePropToFile(ctProp, ctFileName);
		
	}
	//如果用户属性集合s和明文属性集合w重合属性个数不小于d，可按如下方法解密
	//从所有重合属性中选取d个构成属性集合J
	//针对I中的每个属性i，计算Pi=e(Ei,Di)^s(0)=e(g,g)^s*q(i)s(0),其中s(0)是拉格朗日因子
	//E1/Pi连乘就等于明文
	public static Element decrypt(String pairingParametersFileName,String pkFileName,String ctFileName,String skFileName) {
		Pairing bp=PairingFactory.getPairing(pairingParametersFileName);
		//读取配置文件
		Properties pkProp=loadPropFromFile(pkFileName);
		//取出配置文件中的门限值
		String dString=pkProp.getProperty("d");
		int d=Integer.parseInt(dString);
		//取出密文中的属性数组
		Properties ctProp=loadPropFromFile(ctFileName);
		String messageAttListString=ctProp.getProperty("messageAttList");
		int[] messageAttList = Arrays.stream(messageAttListString.substring(1, messageAttListString.length()-1).split(",")).map(String::trim).mapToInt(Integer::parseInt).toArray();

        Properties skProp = loadPropFromFile(skFileName);
        String userAttListString = skProp.getProperty("userAttList");
        //恢复用户属性列表 int[]类型
        int[] userAttList = Arrays.stream(userAttListString.substring(1, userAttListString.length()-1).split(",")).map(String::trim).mapToInt(Integer::parseInt).toArray();

        //判断两个列表重合个数是否小于d
        int[] intersectionAttList = intersection(messageAttList, userAttList);
        System.out.println("重合属性列表：" + Arrays.toString(intersectionAttList));
        System.out.println("重合属性个数为：" + intersectionAttList.length);
        if (intersectionAttList.length < d) {
            System.out.println("不满足解密门限，无法解密！");
            return null;
        }
        //从两个列表中的重合项中取前d项，构成解密属性列表
        int[] decAttList = Arrays.copyOfRange(intersectionAttList, 0, d);
        System.out.println("解密所用属性列表：" + Arrays.toString(decAttList));

        Element denominator = bp.getGT().newOneElement().getImmutable();
        System.out.println("denominator初始值"+denominator);
        //针对解密属性列表中的每个属性，计算e(D,E)^delta，并将结果连乘
        for (int att : decAttList){
            String EString = ctProp.getProperty("E"+att);
            Element E = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(EString)).getImmutable();

            String DString = skProp.getProperty("D"+att);
            Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(DString)).getImmutable();

            //计算属性对应的拉格朗日因子，作为指数。目标值x为0。
            Element delta = lagrange(att, decAttList, 0, bp.getZr()).getImmutable();
            denominator = denominator.mul(bp.pairing(E,D).powZn(delta));
        }
        //System.out.println("输出Y^s的值："+denominator);

        String EPString = ctProp.getProperty("EP");
        Element EP = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(EPString)).getImmutable();
        //恢复M=EP除以上述连乘结果
        Element res = EP.div(denominator);
        return res;
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
	public static Element qx(Element x,Element[] coef,Field Zr) {
		Element res=coef[0];
		for(int i=1;i<coef.length;i++) {
			Element exp=Zr.newElement(i).getImmutable();
			//res=res+coef[i]*x^exp
			res=res.add(coef[i].mul(x.duplicate().powZn(exp)));
		}
		return res;
	}
	public static int[] intersection(int[] nums1,int[] nums2) {
		Arrays.sort(nums1);
		Arrays.sort(nums2);
		int length1=nums1.length;
		int length2=nums2.length;
		int[] intersection=new int[length1+length2];
		int index=0,index1=0,index2=0;
		while(index1<length1 && index2<length2) {
			int num1=nums1[index1],num2=nums2[index2];
			if(num1==num2) {
				if(index==0||num1!=intersection[index-1]) {
					intersection[index++]=num1;
				}
				index1++;
				index2++;
			}else if(num1<num2) {
				index1++;
			}else {
				index2++;
			}
		}
		return Arrays.copyOfRange(intersection, 0, index);
	}
	public static Element lagrange(int i,int[] s,int x,Field Zr) {
		Element res=Zr.newOneElement().getImmutable();
		Element iElement=Zr.newElement(i).getImmutable();
		Element xElement=Zr.newElement(x).getImmutable();
		for(int j:s) {
			if(i!=j) {
				Element numerator=xElement.sub(Zr.newElement(j));
				Element denominator=iElement.sub(Zr.newElement(j));
				res=res.mul(numerator.div(denominator));
			}
		}
		return res;
	}
	public static void main(String[] args) throws Exception {
		// TODO 自动生成的方法存根
		int U = 25;
        int d = 6;
        System.out.println("系统解密门限为：" + d);

        int[] userAttList = {1, 5, 3, 6, 10, 11};
        int[] messageAttList = {1,  3,  5,  7, 9, 10, 11};

        String dir = "data/";
        String pairingParametersFileName = "a.properties";
        String pkFileName = dir + "pk.properties";
        String mskFileName = dir + "msk.properties";
        String skFileName = dir + "sk.properties";
        String ctFileName = dir + "ct.properties";

        setup(pairingParametersFileName, U, d, pkFileName, mskFileName);

        keygen(pairingParametersFileName, userAttList, pkFileName, mskFileName, skFileName);

        Element message = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
        System.out.println("明文消息:" + message);
        encrypt(pairingParametersFileName, message, messageAttList, pkFileName, ctFileName);

        Element res = decrypt(pairingParametersFileName, pkFileName, ctFileName, skFileName);
        System.out.println("解密结果:" + res);
        if (message.isEqual(res)) {
            System.out.println("成功解密！");
		}

	}

}
