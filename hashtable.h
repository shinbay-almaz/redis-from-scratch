#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>

// hashtable node, should be embedded into the payload
struct HNode {
		HNode *next = NULL;
		uint64_t hcode = 0;
};

// a simple fixed-sized hashtable
struct HTab {
		HNode **tab = NULL;
		size_t mask = 0;
		size_t size = 0;
};

struct HMap {
		HTab ht1;
		HTab ht2;
		size_t resizing_pos = 0;
};

struct Entry {
		struct HNode node;
		std::string key;
		std::string val;
};

HNode *hm_lookup(HMap *hmap, HNode *key, bool (*cmp)(HNode *, HNode *));
void hm_insert(HMap *hmap, HNode *node);
HNode *hm_pop(HMap *hmap, HNode *key, bool (*cmp)(HNode *, HNode *));
size_t hm_size(HMap *hmap);

#endif
