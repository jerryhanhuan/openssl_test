#include <algorithm>
#include <vector>
#include <string>
#include <numeric>
#include <math.h>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <iostream>
#include <openssl/sha.h>

#include "hashInterface.h"
#include "str.h"
#include "merkle_tree.h"

using namespace std;


struct Node
{
	unsigned char hash[32];
	Node *left, *right, *parent;
};

int merkle_keccak_hash(unsigned char *data1,unsigned char *data2,unsigned char *hash)
{
	unsigned char buf[128]={0};
	int len = 0;
	memcpy(buf+len,data1,32);
	len+=32;
	if(data2)
	{
		memcpy(buf+len,data2,32);
		len+=32;
	}
	
	return keccak(H_KECCAK_256,buf,len,hash);
}

void printHex(unsigned char *data,int len)
{
	char buf[1024]={0};
	bcdhex_to_aschex((char*)data,len,buf);
	printf("%s\n",buf);
}


void Traverse(const Node* tree)
{
	if(!tree)
		return;
	Traverse(tree->left);
	Traverse(tree->right);
	delete tree;
}


int  MerkleHash(const unsigned char data[][32],int num,unsigned char *out)
{
		
		Node* root;
		vector<Node*> listChild, listParent;
		Node *leftN = nullptr, *rightN = nullptr;
		unsigned char buffer[64]={0};
		int i = 0;
		for (i=0;i<num;i++)
		{
			Node* n = new Node;
			memset(n,0,sizeof(Node));
			memcpy(n->hash,data[i],32);
			n->left = n->right = n->parent = nullptr;
			listChild.push_back(n);
		}
		// And, build the tree over the blocks stored in the list.
		do
		{
			auto iterP = listParent.begin();
			auto doneP = listParent.end();
			while(iterP != doneP)
				listChild.push_back(*iterP++);
			listParent.clear();

			auto iter = listChild.begin();
			auto done = listChild.end();
			leftN = rightN = nullptr;
			while(iter != done)
			{
				//cout << "list: " << child->hashValue << endl;
				if(!leftN)
					leftN = *iter++;
				else
				{
					rightN = *iter++;
					Node *parentN = new Node;
					memset(parentN,0,sizeof(Node));
					merkle_keccak_hash(leftN->hash,rightN->hash,parentN->hash);
					
					
					printf("left::\n");
					printHex(leftN->hash,32);
					printf("right::\n");
					printHex(rightN->hash,32);
					printf("parent::\n");
					printHex(parentN->hash,32);
					
					parentN->left = leftN;
					parentN->right = rightN;
					parentN->parent = nullptr;
					listParent.push_back(parentN);
					leftN->parent = rightN->parent = parentN;
					leftN = rightN = nullptr;
				}
			}

			//cout << endl;
			if(leftN)
			{
				
				// Make a new NULL node:
				rightN = new Node;
				memset(rightN,0,sizeof(Node));
				rightN->left = rightN->right = nullptr;

				Node *parentN = new Node;
				memset(parentN,0,sizeof(Node));
				merkle_keccak_hash(leftN->hash,NULL,parentN->hash);
				
				printf("left::\n");
				printHex(leftN->hash,32);
				printf("parent::\n");
				printHex(parentN->hash,32);
				

				parentN->left = leftN;
				parentN->right = rightN;
				parentN->parent = nullptr;
				listParent.push_back(parentN);
				leftN->parent = rightN->parent = parentN;
				leftN = rightN = nullptr;
			}

			listChild.clear();
		}while(listParent.size() > 1);

		root = listParent[0];
		memcpy(out,root->hash,32);
		Traverse(root);
		return 32;
	}





#if 0
int main()
{
	MerkleHash();
	system("pause");
	return 0;

}
#endif