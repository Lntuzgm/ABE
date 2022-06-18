import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;

public class Node {
	public int[] gate;
	public String att;
	public int parent;
	public int[] children;
	public Element secretShare;
	public boolean comb=false;
	public Node(int parent,int[] gate,int[] children) {
		this.parent=parent;
		this.gate=gate;
		this.children=children;
	}
	public Node(int parent,String att) {
		this.parent=parent;
		this.att=att;
	}
	public boolean isLeaf() {
		return this.children==null ? true : false;
	}
	@Override
	public String toString() {
		return "Node [gate=" + Arrays.toString(gate) + ", att=" + att + ", parent=" + parent + ", children="
				+ Arrays.toString(children) + ", secretShare=" + secretShare + ", comb=" + comb + "]";
	}
	
	
	

}
