
package bilinear;

import it.unisa.dia.gas.jpbc.*;  
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory; 

/**
 * @author Donlin
 *
 */
public class JPBC {

	//获取当前工作目录
	static final String packagePath = System.getProperty("user.dir");
	static final String sourcePath = packagePath+"/sources/";
	
	//双线性映射方案参数
    private Element s, r, P, Ppub, Su, Qu, Ku, V, T1, T2;  
    private Field<Element> G1, Zr;  
    private Pairing pairing; 
	
    public  JPBC() {
    	// 构造函数
        init();  
    }  
  
    /** 
    * 初始化 
    */  
	private void init() {  
		//Notice that, to effectively use the wrapper the usePBCWhenPossible property must be set before invoking the getPairing method.
		PairingFactory.getInstance().setUsePBCWhenPossible(true);
		//配置文件，椭圆曲线的相关参数已经存储在params文件夹，后缀为.properties
		pairing = PairingFactory.getPairing(packagePath + "/params/curves/a.properties");  
		//检查密钥是否对称
        checkSymmetric(pairing);  
        //初始化Zr环，之后的r将初始化为Zr中的元素
        Zr = pairing.getZr();    
        //将变量Ppub，Qu，Su，V初始化为G1中的元素，G1是加法群  
        G1 = pairing.getG1();  
        Ppub = G1.newElement();  
        Qu = G1.newElement();  
        Su = G1.newElement();  
        V = G1.newElement();  
        //将变量T1，T2初始化为GT中的元素，GT是乘法群  
        Field<Element> GT = pairing.getGT();  
        T1 = GT.newElement(); 
        T2 = GT.newElement();  
    }  
  
    /** 
     * 判断配对是否为对称配对，不对称则输出错误信息 
     *  
     * @param pairing 
     */  
    private void checkSymmetric(Pairing pairing) {  
        if (!pairing.isSymmetric()) {  
            throw new RuntimeException("密钥不对称!");  
        }  
    }  
  
    public Element buildSystem() {  
        System.out.println("-------------------系统建立阶段----------------------"); 
        // 在循环环Zr上随机生成主密钥s，
        s = Zr.newRandomElement().getImmutable();  
        // 生成G1的生成元P，G1是素数群，每一个元素都是生成元
        P = G1.newRandomElement().getImmutable();
        // 计算Ppub=s * P,注意顺序
        Ppub = P.mulZn(s).getImmutable();  
        System.out.println("P=" + P);  
        System.out.println("s=" + s);  
        System.out.println("Ppub=" + Ppub);  
        return Ppub;
    }  
    
    public Element extractSecretKey(String keyword) {  
        System.out.println("-------------------密钥提取阶段----------------------");  
        //将“ID”这个字符进行哈希计算之后映射到G1群上某一个元素，构造关键字的时候可以在这一步构造  
        Qu = pairing.getG1().newElement().setFromHash(keyword.getBytes(), 0, keyword.length()).getImmutable();
        //Ku = pairing.getG1().newElement().setFromHash("urgent".getBytes(),0, "urgent".length()).getImmutable();
      
        
        System.out.println("keyword.length = " + keyword.length());
        //System.out.println("urgent .length = " + "urgent".length());
        System.out.println("Qu=" + Qu);
        //System.out.println("Ku=" + Ku);
        System.out.println("Su=" + Su);  
        return Qu;
    }  
  
    public Element encrypt(Element pubkey,Element keywordInG1) {  
        System.out.println("-------------------加密阶段----------------------");
        //随机选取一个r值用于计算隐藏公钥和私钥
        //r = Zr.newElement(123456).getImmutable(); 
        //计算v=r * P  
        //V = P.mulZn(r);  
        //计算e（Ppub,Qu）  
        T1 = pairing.pairing(pubkey, keywordInG1).getImmutable();
        //计算e（Ppub,Qu）^r， 相当于
        //T1 = T1.powZn(r).getImmutable();  
        //System.out.println("r=" + r);  
        System.out.println("V=" + V);  
        System.out.println("T1=e（Ppub,Qu）=" + T1);
        return T1;
    }  
  
    public Element bulidTrapdoor(String wantedWord) {
    	Ku = pairing.getG1().newElement().setFromHash(wantedWord.getBytes(), 0, wantedWord.length()).getImmutable();
    	//计算Su=s * Qu 
        Su = Ku.mulZn(s).getImmutable();
		return Su;
	}
    
    public Element decrypt(Element trapdoor) {  
        //System.out.println("-------------------验证阶段----------------------");  
        T2 = pairing.pairing(P, trapdoor).getImmutable();  
        //System.out.println("T2 = e(V,Su)=" + T2);  
        // 求V的字节长度，假设消息长度为128字节
        //int byt = V.getLengthInBytes();  
        //System.out.println("文本长度" + byt);  
        return T2;
    }
}
