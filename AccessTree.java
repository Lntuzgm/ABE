import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class AccessTree {
	
	public static void ChildrenTree(Node[] childrenTree,Node[] nodes,int index) {
		if(nodes[index].isLeaf()) {
			childrenTree[index]=nodes[index];
			return ;
		}
		if(!nodes[index].isLeaf()) {
			childrenTree[index]=nodes[index];
			for(int i=0;i<nodes[index].children.length;i++){
				ChildrenTree(childrenTree, nodes, nodes[index].children[i]);
			}
			return;
		}
	}
	public static void printTree(Node[] nodes) {
		for(int i=0;i<nodes.length;i++) {
			if(nodes[i]!=null)
			System.out.println(nodes[i].toString());
		}
		
	}
	//计算各个随机多项式的系数,d是门限值，s是秘密值
	public static Element[] RandomPolynomial(int d,Element s,Pairing bp) {
		Element[] vals=new Element[d];
		vals[0]=s;
		for(int i=1;i<d;i++) {
			vals[i]=bp.getZr().newRandomElement().getImmutable();
		}
		return vals;
	}
	//返回节点index处的秘密值，vals是随机多项式的系数数组，
	public static Element SecretValue(Element[] vals,Element index,Pairing bp) {
		Element value=vals[0].getImmutable();
		for(int i=1;i<vals.length;i++) {
			Element ind=bp.getZr().newElement(i).getImmutable();
			value=value.add(vals[i].mul(index.duplicate().powZn(ind)));
		}
		return value;
		
	}
	//计算拉格朗日因子值
	public static Element largrange(int rvalue,int[] s,int x,Pairing bp) {
		Element result=bp.getZr().newOneElement().getImmutable();
		Element relement=bp.getZr().newElement(rvalue).getImmutable();
		Element xelement=bp.getZr().newElement(x).getImmutable();
		for(int j:s) {
			if(rvalue!=j) {
				Element numerator=xelement.sub(bp.getZr().newElement(j));
				Element denominator=relement.sub(bp.getZr().newElement(j));
				result=result.mul(numerator.div(denominator));
			}
		}
		return result;
		
	}
	public static void SharingSecret(Node[] nodes,Node node,Pairing bp) {
		
		if(!node.isLeaf()) {
			//返回一个随机多项式的系数，Element[0]是秘密值
			Element[] e=RandomPolynomial(node.gate[0], node.secretShare, bp);
			for(int i=0;i<node.children.length;i++) {
				Node nchildren=nodes[node.children[i]];
				nchildren.secretShare=SecretValue(e, bp.getZr().newElement(node.children[i]), bp);
				SharingSecret(nodes, nchildren,bp);
			}
			
		}
}
	//判断属性是否在访问数中
	public static void Attributes(Node node,String[] atts) {
		int m=atts.length;
		for(int i=0;i<m;i++) {
			if(atts[i].equals(node.att))
				node.comb=true;
		}
	}
	//秘密恢复
	public static boolean SecretSynthesis(Node[] nodes,Node node,String[] atts,Pairing bp) {
		if(!node.isLeaf()) {
			int gates=0;
			int[] childrens=new int[node.gate[0]];
			int len=node.children.length;
			for(int i=0;i<len;i++) {
				Node nodechildren=nodes[node.children[i]];
				if(SecretSynthesis(nodes, nodechildren,atts,bp)) {
					childrens[gates]=node.children[i];
					gates++;
					if(gates==node.gate[0]) {
						node.comb=true;
						Element secret=bp.getZr().newZeroElement().getImmutable();
						for(int j=0;j<childrens.length;j++) {
								Element factor=largrange(childrens[j], childrens, 0, bp);
								secret=secret.add(nodes[childrens[j]].secretShare.duplicate().mul(factor));
						}
						node.secretShare=secret;	
						break;
					}	
				}
				
			}
		
		}else {
			Attributes(node, atts);
		}
	return node.comb;	
}
   
	public static void main(String[] args) {
		// TODO 自动生成的方法存根
		Pairing bp=PairingFactory.getPairing("a.properties");
		Node[] nodes=new Node[9];
		nodes[0]=new Node(0,new int[] {2,3}, new int[] {1,2,3});
		nodes[1]=new Node(0,new int[] {2,3},new int[] {4,5,6});
		nodes[2]=new Node(0,new int[] {1,2},new int[] {7,8});
		nodes[3]=new Node(0,"工大老师");
		nodes[4]=new Node(1,"本科生");
		nodes[5]=new Node(1,"硕士生");
		nodes[6]=new Node(1,"博士生");
		nodes[7]=new Node(2,"软件学院");
		nodes[8]=new Node(2,"计算机学院");
		nodes[0].secretShare=bp.getZr().newElement(10);
		printTree(nodes);
		SharingSecret(nodes, nodes[0],bp);
		printTree(nodes);
		String[] atts= {"软件学院","工大老师"};
		for(int i=0;i<nodes.length;i++) {
//			Attributes(nodes[i],atts);
			if(!nodes[i].isLeaf()) {
				nodes[i].secretShare=null;
			}
		}
		System.out.println("清空访问树");
		printTree(nodes);
		boolean b=SecretSynthesis(nodes, nodes[0],atts, bp);
		System.out.println(b);
		
		if(b) {
			System.out.println("访问树的密钥是："+nodes[0].secretShare);
		}else {
			System.out.println("无法恢复出密钥值!");
		}
		printTree(nodes);
//		Node[] childrenTree=new Node[nodes.length];
//		ChildrenTree(childrenTree, nodes, 3);
//		printTree(childrenTree);
		

	}

}

