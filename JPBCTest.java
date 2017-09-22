
package bilinear;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import it.unisa.dia.gas.jpbc.*;  

/**
 * @author Donlin
 * 测试PEKS方案搜索关键字
 */
public class JPBCTest {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO 自动生成的方法存根
		//文件读取路径选择
    	File sourFile = new File(JPBC.sourcePath);
    	//建立一个字典记录文档序号对应的PEKS密文
    	Map<Object, Object> dec = new HashMap<>();
    	//初始化一个JPBC计算方案
    	JPBC jpbcCipher = new JPBC();
    	//构建一个jpbc方案，初始化其参数，输出公钥pPubkey
    	Element pPubkey = jpbcCipher.buildSystem();
    	//记录读取的文档数
    	int i = 1;
    	//检查sourFile存在以及是否为目录
    	if(sourFile.exists() && sourFile.isDirectory()){
    		//对目录下每个文件进行读取
    		for(File sourTemp: sourFile.listFiles()){   
    			BufferedReader in = null;
    			try {
    				System.out.println("File:" + i);
    				//开辟一个读取文件的字符缓冲流
    				in = new BufferedReader(new FileReader(sourTemp));
    				//读取首行字符
    				String temp = in.readLine();
    				//提取关键字subject:后的内容
    				String keyWord = temp.substring(temp.indexOf(":")+1);
    				//这里进行双线性映射函数的计算，将关键字映射到群G1中的元素，并使用公钥pPubkey进行加密
    				Element keyWordInG1 = jpbcCipher.extractSecretKey(keyWord);
    				Element encResult = jpbcCipher.encrypt(pPubkey,keyWordInG1);
    				//添加到字典中
    				dec.put(sourTemp.getName(), encResult);
    				i++;
    			}catch (Exception e) {
					// TODO: handle exception
    				e.printStackTrace();
				}
    			
    		}
    	}
    	System.out.println(dec);
    	//读取屏幕输入
    	System.out.println("输入要查询的关键字:");
    	Scanner scan = new Scanner(System.in);
    	String choice = scan.nextLine();
    	//检查输入字符
    	while(!choice.equals("0")){
    		int j = 0;//记录文件数
    		System.out.println("包含该关键字的文档:");
    		//构造要查询的关键字的陷门
    		Element trapDoor = jpbcCipher.bulidTrapdoor(choice);
    		//遍历字典并通过陷门计算匹配的关键字
    		for(Object temp: dec.keySet()){
    			if(jpbcCipher.decrypt(trapDoor).isEqual((Element) dec.get(temp))){
    				System.out.println(temp.toString());
    				j++;
    			}
    		}
    		if(j == 0){
    			System.out.println("未找到匹配的文件！");
    		}
    		//继续读取下一行输入
    		System.out.println("输入要查询的关键字:");
    		choice = scan.nextLine();
    	}
    	System.out.println("Over!");
    	//关闭输入流
    	scan.close();
	}

}
