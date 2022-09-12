#define LUA_LIB

#include "skynet_malloc.h"

#include "skynet_socket.h"

#include <lua.h>
#include <lauxlib.h>

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define QUEUESIZE 1024 * 64
#define HASHSIZE 40960
#define SMALLSTRING 1024 * 64

#define TYPE_DATA 1
#define TYPE_MORE 2
#define TYPE_ERROR 3
#define TYPE_OPEN 4
#define TYPE_CLOSE 5
#define TYPE_WARNING 6

/*
	Each package is uint16 + data , uint16 (serialized in big-endian) is the number of bytes comprising the data .
 */

struct netpack {
	int id;
	int size;
	void * buffer;
	int8_t flag;
	uint16_t cmd;
    int8_t version;
    int8_t subversion;	
};

struct uncomplete {
	struct netpack pack;
	struct uncomplete * next;
	int read;
	int check_code;
	int8_t flag;
	//int header;
};

struct queue {
	int cap;
	int head;
	int tail;
	struct uncomplete * hash[HASHSIZE];
	struct netpack queue[QUEUESIZE];
};

static void
clear_list(struct uncomplete * uc) {
	while (uc) {
		skynet_free(uc->pack.buffer);
		void * tmp = uc;
		uc = uc->next;
		skynet_free(tmp);
	}
}


///////////////////////////////////////////////////
#define MY_HEADER_SIZE 13


struct my_header {
    int8_t flag[2];
    uint16_t cmd;
    int8_t version;
    int8_t subversion;
    uint16_t length; //short
    int8_t code;
    int32_t seq;
};

static const uint16_t recv_byte_map[256] = {
    0x51, 0xA1, 0x9E, 0xB0, 0x1E, 0x83, 0x1C, 0x2D, 0xE9, 0x77, 0x3D, 0x13, 0x93, 0x10, 0x45, 0xFF,
    0x6D, 0xC9, 0x20, 0x2F, 0x1B, 0x82, 0x1A, 0x7D, 0xF5, 0xCF, 0x52, 0xA8, 0xD2, 0xA4, 0xB4, 0x0B,
    0x31, 0x97, 0x57, 0x19, 0x34, 0xDF, 0x5B, 0x41, 0x58, 0x49, 0xAA, 0x5F, 0x0A, 0xEF, 0x88, 0x01,
    0xDC, 0x95, 0xD4, 0xAF, 0x7B, 0xE3, 0x11, 0x8E, 0x9D, 0x16, 0x61, 0x8C, 0x84, 0x3C, 0x1F, 0x5A,
    0x02, 0x4F, 0x39, 0xFE, 0x04, 0x07, 0x5C, 0x8B, 0xEE, 0x66, 0x33, 0xC4, 0xC8, 0x59, 0xB5, 0x5D,
    0xC2, 0x6C, 0xF6, 0x4D, 0xFB, 0xAE, 0x4A, 0x4B, 0xF3, 0x35, 0x2C, 0xCA, 0x21, 0x78, 0x3B, 0x03,
    0xFD, 0x24, 0xBD, 0x25, 0x37, 0x29, 0xAC, 0x4E, 0xF9, 0x92, 0x3A, 0x32, 0x4C, 0xDA, 0x06, 0x5E,
    0x00, 0x94, 0x60, 0xEC, 0x17, 0x98, 0xD7, 0x3E, 0xCB, 0x6A, 0xA9, 0xD9, 0x9C, 0xBB, 0x08, 0x8F,
    0x40, 0xA0, 0x6F, 0x55, 0x67, 0x87, 0x54, 0x80, 0xB2, 0x36, 0x47, 0x22, 0x44, 0x63, 0x05, 0x6B,
    0xF0, 0x0F, 0xC7, 0x90, 0xC5, 0x65, 0xE2, 0x64, 0xFA, 0xD5, 0xDB, 0x12, 0x7A, 0x0E, 0xD8, 0x7E,
    0x99, 0xD1, 0xE8, 0xD6, 0x86, 0x27, 0xBF, 0xC1, 0x6E, 0xDE, 0x9A, 0x09, 0x0D, 0xAB, 0xE1, 0x91,
    0x56, 0xCD, 0xB3, 0x76, 0x0C, 0xC3, 0xD3, 0x9F, 0x42, 0xB6, 0x9B, 0xE5, 0x23, 0xA7, 0xAD, 0x18,
    0xC6, 0xF4, 0xB8, 0xBE, 0x15, 0x43, 0x70, 0xE0, 0xE7, 0xBC, 0xF1, 0xBA, 0xA5, 0xA6, 0x53, 0x75,
    0xE4, 0xEB, 0xE6, 0x85, 0x14, 0x48, 0xDD, 0x38, 0x2A, 0xCC, 0x7F, 0xB1, 0xC0, 0x71, 0x96, 0xF8,
    0x3F, 0x28, 0xF2, 0x69, 0x74, 0x68, 0xB7, 0xA3, 0x50, 0xD0, 0x79, 0x1D, 0xFC, 0xCE, 0x8A, 0x8D,
    0x2E, 0x62, 0x30, 0xEA, 0xED, 0x2B, 0x26, 0xB9, 0x81, 0x7C, 0x46, 0x89, 0x73, 0xA2, 0xF7, 0x72
};
static const uint16_t send_byte_map[256] = {
    0x70, 0x2F, 0x40, 0x5F, 0x44, 0x8E, 0x6E, 0x45, 0x7E, 0xAB, 0x2C, 0x1F, 0xB4, 0xAC, 0x9D, 0x91,
    0x0D, 0x36, 0x9B, 0x0B, 0xD4, 0xC4, 0x39, 0x74, 0xBF, 0x23, 0x16, 0x14, 0x06, 0xEB, 0x04, 0x3E,
    0x12, 0x5C, 0x8B, 0xBC, 0x61, 0x63, 0xF6, 0xA5, 0xE1, 0x65, 0xD8, 0xF5, 0x5A, 0x07, 0xF0, 0x13,
    0xF2, 0x20, 0x6B, 0x4A, 0x24, 0x59, 0x89, 0x64, 0xD7, 0x42, 0x6A, 0x5E, 0x3D, 0x0A, 0x77, 0xE0,
    0x80, 0x27, 0xB8, 0xC5, 0x8C, 0x0E, 0xFA, 0x8A, 0xD5, 0x29, 0x56, 0x57, 0x6C, 0x53, 0x67, 0x41,
    0xE8, 0x00, 0x1A, 0xCE, 0x86, 0x83, 0xB0, 0x22, 0x28, 0x4D, 0x3F, 0x26, 0x46, 0x4F, 0x6F, 0x2B,
    0x72, 0x3A, 0xF1, 0x8D, 0x97, 0x95, 0x49, 0x84, 0xE5, 0xE3, 0x79, 0x8F, 0x51, 0x10, 0xA8, 0x82,
    0xC6, 0xDD, 0xFF, 0xFC, 0xE4, 0xCF, 0xB3, 0x09, 0x5D, 0xEA, 0x9C, 0x34, 0xF9, 0x17, 0x9F, 0xDA,
    0x87, 0xF8, 0x15, 0x05, 0x3C, 0xD3, 0xA4, 0x85, 0x2E, 0xFB, 0xEE, 0x47, 0x3B, 0xEF, 0x37, 0x7F,
    0x93, 0xAF, 0x69, 0x0C, 0x71, 0x31, 0xDE, 0x21, 0x75, 0xA0, 0xAA, 0xBA, 0x7C, 0x38, 0x02, 0xB7,
    0x81, 0x01, 0xFD, 0xE7, 0x1D, 0xCC, 0xCD, 0xBD, 0x1B, 0x7A, 0x2A, 0xAD, 0x66, 0xBE, 0x55, 0x33,
    0x03, 0xDB, 0x88, 0xB2, 0x1E, 0x4E, 0xB9, 0xE6, 0xC2, 0xF7, 0xCB, 0x7D, 0xC9, 0x62, 0xC3, 0xA6,
    0xDC, 0xA7, 0x50, 0xB5, 0x4B, 0x94, 0xC0, 0x92, 0x4C, 0x11, 0x5B, 0x78, 0xD9, 0xB1, 0xED, 0x19,
    0xE9, 0xA1, 0x1C, 0xB6, 0x32, 0x99, 0xA3, 0x76, 0x9E, 0x7B, 0x6D, 0x9A, 0x30, 0xD6, 0xA9, 0x25,
    0xC7, 0xAE, 0x96, 0x35, 0xD0, 0xBB, 0xD2, 0xC8, 0xA2, 0x08, 0xF3, 0xD1, 0x73, 0xF4, 0x48, 0x2D,
    0x90, 0xCA, 0xE2, 0x58, 0xC1, 0x18, 0x52, 0xFE, 0xDF, 0x68, 0x98, 0x54, 0xEC, 0x60, 0x43, 0x0F
};

static int 
by_pack_decrypt(uint8_t *packet, int begin_pos, int data_size, int check_code) {
    uint8_t *temp = (uint8_t *) packet + begin_pos;
    int i;
    for (i = 0; i < data_size; i++) {
        temp[i] = recv_byte_map[temp[i]];
        check_code += temp[i];
    }
    if ((check_code % 256) != 0) {
        return 1;
    }
    return 0;
}

static int 
by_pack_encrypt(uint8_t *packet, int begin_pos, int data_size) {
    uint8_t *temp = (uint8_t *) packet;
    uint8_t check_code = 0;
    uint16_t i;
    for (i = begin_pos; i < data_size + begin_pos; i++) {
        check_code += temp[i];
        packet[i] = send_byte_map[temp[i]];
    }
    return ~check_code + 1;
}
///////////////////////////////////////////////////

static int
lclear(lua_State *L) {
	struct queue * q = lua_touserdata(L, 1);
	if (q == NULL) {
		return 0;
	}
	int i;
	for (i=0;i<HASHSIZE;i++) {
		clear_list(q->hash[i]);
		q->hash[i] = NULL;
	}
	if (q->head > q->tail) {
		q->tail += q->cap;
	}
	for (i=q->head;i<q->tail;i++) {
		struct netpack *np = &q->queue[i % q->cap];
		skynet_free(np->buffer);
	}
	q->head = q->tail = 0;

	return 0;
}

static inline int
hash_fd(int fd) {
	int a = fd >> 24;
	int b = fd >> 12;
	int c = fd;
	return (int)(((uint32_t)(a + b + c)) % HASHSIZE);
}

static struct uncomplete *
find_uncomplete(struct queue *q, int fd) {
	if (q == NULL)
		return NULL;
	int h = hash_fd(fd);
	struct uncomplete * uc = q->hash[h];
	if (uc == NULL)
		return NULL;
	if (uc->pack.id == fd) {
		q->hash[h] = uc->next;
		return uc;
	}
	struct uncomplete * last = uc;
	while (last->next) {
		uc = last->next;
		if (uc->pack.id == fd) {
			last->next = uc->next;
			return uc;
		}
		last = uc;
	}
	return NULL;
}

static struct queue *
get_queue(lua_State *L) {
	struct queue *q = lua_touserdata(L,1);
	if (q == NULL) {
		q = lua_newuserdatauv(L, sizeof(struct queue), 0);
		q->cap = QUEUESIZE;
		q->head = 0;
		q->tail = 0;
		int i;
		for (i=0;i<HASHSIZE;i++) {
			q->hash[i] = NULL;
		}
		lua_replace(L, 1);
	}
	return q;
}

static void
expand_queue(lua_State *L, struct queue *q) {
	struct queue *nq = lua_newuserdatauv(L, sizeof(struct queue) + q->cap * sizeof(struct netpack), 0);
	nq->cap = q->cap + QUEUESIZE;
	nq->head = 0;
	nq->tail = q->cap;
	memcpy(nq->hash, q->hash, sizeof(nq->hash));
	memset(q->hash, 0, sizeof(q->hash));
	int i;
	for (i=0;i<q->cap;i++) {
		int idx = (q->head + i) % q->cap;
		nq->queue[i] = q->queue[idx];
	}
	q->head = q->tail = 0;
	lua_replace(L,1);
}

static void
push_data(lua_State *L, int fd, void *buffer, int size, int clone, 
	int check_code, int8_t flag, uint16_t cmd, int8_t version, int8_t subversion) {
	if (clone) {
		void * tmp = skynet_malloc(size);
		memcpy(tmp, buffer, size);
		buffer = tmp;	
	}
	if (check_code != 0 && flag == 1) {
		int ret = by_pack_decrypt(buffer, 0, size, check_code);
		if (ret != 0) {
			return;
		}
	}		
	struct queue *q = get_queue(L);
	struct netpack *np = &q->queue[q->tail];
	if (++q->tail >= q->cap)
		q->tail -= q->cap;
	np->id = fd;
	np->buffer = buffer;
	np->size = size;
	np->flag = flag;
	np->cmd = cmd;
	np->version = version;
	np->subversion = subversion;
	if (q->head == q->tail) {
		expand_queue(L, q);
	}	
}

static struct uncomplete *
save_uncomplete(lua_State *L, int fd) {
	struct queue *q = get_queue(L);
	int h = hash_fd(fd);
	struct uncomplete * uc = skynet_malloc(sizeof(struct uncomplete));
	memset(uc, 0, sizeof(*uc));
	uc->next = q->hash[h];
	uc->pack.id = fd;
	q->hash[h] = uc;

	return uc;
}

static inline int
read_size(uint8_t * buffer) {
	int r = (int)buffer[0] << 8 | (int)buffer[1];
	return r;
}

static void
push_more(lua_State *L, int fd, uint8_t *buffer, int size) {
	if (size < MY_HEADER_SIZE) {
		struct uncomplete * uc = save_uncomplete(L, fd);
		uc->read = - 1;
		uc->pack.size = size;
		uc->pack.buffer = skynet_malloc(size);
		memcpy(uc->pack.buffer, buffer, size);
		return;
	}
	
	int packet_check_code = 0;
	int8_t flag;
	uint16_t cmd = 0;
    int8_t version = 0;
    int8_t subversion = 0;
    	
	char magic[3];
	memset(magic, 0, sizeof(magic));
	memcpy(magic, buffer, sizeof(magic) -1);
	if (!strncasecmp(magic, "MY", sizeof("MY")-1)) {
		flag = 1;
	} else {
		flag = 0;
	}
		
	int pack_size;
	if(flag == 1) {
		struct my_header * i_header = (struct my_header*) buffer;
		pack_size = i_header->length;
		packet_check_code = i_header->code;
		cmd = i_header->cmd;
		version = i_header->version;
		subversion = i_header->subversion;
		buffer += MY_HEADER_SIZE;
		size -= MY_HEADER_SIZE;
	} else {
		pack_size = read_size(buffer);
		buffer += 2;
		size -= 2;
	}
	
	if (size < pack_size) {
		struct uncomplete * uc = save_uncomplete(L, fd);
		uc->read = size;
		uc->flag = flag;
		uc->check_code = packet_check_code;
		uc->pack.flag = flag;
		uc->pack.cmd = cmd;
		uc->pack.version = version;
		uc->pack.subversion = subversion;
		uc->pack.size = pack_size;
		uc->pack.buffer = skynet_malloc(pack_size);
		memcpy(uc->pack.buffer, buffer, size);
		return;
	}

	push_data(L, fd, buffer, pack_size, 1, packet_check_code, flag, cmd, version, subversion);

	buffer += pack_size;
	size -= pack_size;
	if (size > 0) {
		push_more(L, fd, buffer, size);
	}
}

static void
close_uncomplete(lua_State *L, int fd) {
	struct queue *q = lua_touserdata(L,1);
	struct uncomplete * uc = find_uncomplete(q, fd);
	if (uc) {
		skynet_free(uc->pack.buffer);
		skynet_free(uc);
	}
}

static int
filter_data_(lua_State *L, int fd, uint8_t * buffer, int size) {
	struct queue *q = lua_touserdata(L,1);
	struct uncomplete * uc = find_uncomplete(q, fd);
	if (uc) {
		// fill uncomplete
		if (uc->read < 0) {
			if ((uc->pack.size + size) >= MY_HEADER_SIZE) {
				uint8_t * temp_buffer = skynet_malloc((uc->pack.size+size));
				memcpy(temp_buffer, uc->pack.buffer, uc->pack.size);
				memcpy(temp_buffer+uc->pack.size, buffer, size);

				int8_t flag;
				uint16_t cmd = 0;
				int8_t version = 0;
				int8_t subversion = 0;				
				char magic[3];
				memset(magic, 0, sizeof(magic));
				memcpy(magic, temp_buffer, sizeof(magic) -1);
				if (!strncasecmp(magic, "MY", sizeof("MY")-1)) {
					flag = 1;
				} else {
					flag = 0;
				}
				int pack_size;
				if(flag == 1) {
					struct my_header * i_header = (struct my_header*) temp_buffer;
					cmd = i_header->cmd;
					version = i_header->version;
					subversion = i_header->subversion;
					pack_size = i_header->length;
					buffer += (MY_HEADER_SIZE - uc->pack.size);
					size -= (MY_HEADER_SIZE - uc->pack.size);
					uc->pack.flag = flag;
					uc->pack.cmd = cmd;
					uc->pack.version = version;
					uc->pack.subversion = subversion;					
					uc->pack.size = pack_size;
					uc->pack.buffer = skynet_malloc(pack_size);
					uc->read = 0;
					uc->check_code = i_header->code;
					uc->flag = flag;									
				} else {
					pack_size = read_size(temp_buffer);
					if (uc->pack.size == 1) {
						buffer += 1;
						size -= 1;					
					} else {
						buffer += 2;
						size -= 2;
					}
					uc->pack.flag = flag;
					uc->pack.cmd = cmd;
					uc->pack.version = version;
					uc->pack.subversion = subversion;					
					uc->pack.size = pack_size;
					uc->pack.buffer = skynet_malloc(pack_size);
					uc->read = 0;
					uc->check_code = 0;
					uc->flag = flag;
				}
				skynet_free(temp_buffer);					
			} else {
				memcpy(uc->pack.buffer + uc->pack.size, buffer, size);
				uc->read = uc->pack.size + size;
				int h = hash_fd(fd);
				uc->next = q->hash[h];
				q->hash[h] = uc;
				return 1;			
			}
		}
		
		int need = uc->pack.size - uc->read;
		if (size < need) {
			memcpy(uc->pack.buffer + uc->read, buffer, size);
			uc->read += size;
			int h = hash_fd(fd);
			uc->next = q->hash[h];
			q->hash[h] = uc;
			return 1;
		}
		memcpy(uc->pack.buffer + uc->read, buffer, need);
		buffer += need;
		size -= need;
		if (size == 0) {
			if (uc->check_code != 0 && uc->flag == 1) {
				int ret = by_pack_decrypt(uc->pack.buffer, 0, uc->pack.size, uc->check_code);
				if (ret != 0) {
					lua_pushvalue(L, lua_upvalueindex(TYPE_DATA));
					lua_pushinteger(L, fd);
					lua_pushlightuserdata(L, &ret);
					lua_pushinteger(L, 0);
					lua_pushinteger(L, uc->pack.flag);
					lua_pushinteger(L, uc->pack.cmd);
					lua_pushinteger(L, uc->pack.version);
					lua_pushinteger(L, uc->pack.subversion);
					skynet_free(uc);
					return 9;			
				}
			}			
			lua_pushvalue(L, lua_upvalueindex(TYPE_DATA));
			lua_pushinteger(L, fd);
			lua_pushlightuserdata(L, uc->pack.buffer);
			lua_pushinteger(L, uc->pack.size);
			lua_pushinteger(L, uc->pack.flag);
			lua_pushinteger(L, uc->pack.cmd);
			lua_pushinteger(L, uc->pack.version);
			lua_pushinteger(L, uc->pack.subversion);
			skynet_free(uc);
			return 9;
		}
		
		// more data
		push_data(L, fd, uc->pack.buffer, uc->pack.size, 0, uc->check_code, uc->flag, 
		uc->pack.cmd, uc->pack.version, uc->pack.subversion);
		skynet_free(uc);
		push_more(L, fd, buffer, size);
		lua_pushvalue(L, lua_upvalueindex(TYPE_MORE));
		return 2;
	} else {
		if (size < MY_HEADER_SIZE) {
			struct uncomplete * uc = save_uncomplete(L, fd);
			uc->read = - 1;
			uc->pack.size = size;
			uc->pack.buffer = skynet_malloc(size);
			memcpy(uc->pack.buffer, buffer, size);
			return 1;
		}
		
		int flag;
		int packet_check_code = 0;
		uint16_t cmd = 0;
		int8_t version = 0;
		int8_t subversion = 0;
						
		char magic[3];
		memset(magic, 0, sizeof(magic));
		memcpy(magic, buffer, sizeof(magic) -1);
		if (!strncasecmp(magic, "MY", sizeof("MY")-1)) {
			flag = 1;
		} else {
			flag = 0;
		}
		
		int pack_size;
		if(flag == 1) {
			struct my_header * i_header = (struct my_header*) buffer;
			pack_size = i_header->length;
			cmd = i_header->cmd;
			version = i_header->version;
			subversion = i_header->subversion;
			packet_check_code = i_header->code;		
			buffer += MY_HEADER_SIZE;
			size -= MY_HEADER_SIZE;
		} else {
			pack_size = read_size(buffer);
			buffer += 2;
			size -= 2;
		}
		
		if (size < pack_size) {
			struct uncomplete * uc = save_uncomplete(L, fd);
			uc->read = size;
			uc->flag = flag;
			uc->check_code = packet_check_code;
			uc->pack.flag = flag;
			uc->pack.cmd = cmd;
			uc->pack.version = version;
			uc->pack.subversion = subversion;
			uc->pack.size = pack_size;
			uc->pack.buffer = skynet_malloc(pack_size);
			memcpy(uc->pack.buffer, buffer, size);
			return 1;
		}
		if (size == pack_size) {
			// just one package
			if (packet_check_code != 0 && flag == 1) {
				int ret = by_pack_decrypt(buffer, 0, pack_size, packet_check_code);
				if (ret != 0) {
					lua_pushvalue(L, lua_upvalueindex(TYPE_DATA));
					lua_pushinteger(L, fd);
					lua_pushlightuserdata(L, &ret);
					lua_pushinteger(L, 0);
					lua_pushinteger(L, flag);
					lua_pushinteger(L, cmd);
					lua_pushinteger(L, version);
					lua_pushinteger(L, subversion);			
					return 9;				
				}
			}			
			lua_pushvalue(L, lua_upvalueindex(TYPE_DATA));
			lua_pushinteger(L, fd);
			void * result = skynet_malloc(pack_size);
			memcpy(result, buffer, size);
			lua_pushlightuserdata(L, result);
			lua_pushinteger(L, size);
			lua_pushinteger(L, flag);
			lua_pushinteger(L, cmd);
			lua_pushinteger(L, version);
			lua_pushinteger(L, subversion);			
			return 9;
		}
		// more data
		push_data(L, fd, buffer, pack_size, 1, packet_check_code, flag, cmd ,version, subversion);
		buffer += pack_size;
		size -= pack_size;
		push_more(L, fd, buffer, size);
		lua_pushvalue(L, lua_upvalueindex(TYPE_MORE));
		return 2;
	}
}

static inline int
filter_data(lua_State *L, int fd, uint8_t * buffer, int size) {
	int ret = filter_data_(L, fd, buffer, size);
	// buffer is the data of socket message, it malloc at socket_server.c : function forward_message .
	// it should be free before return,
	skynet_free(buffer);
	return ret;
}

static void
pushstring(lua_State *L, const char * msg, int size) {
	if (msg) {
		lua_pushlstring(L, msg, size);
	} else {
		lua_pushliteral(L, "");
	}
}

/*
	userdata queue
	lightuserdata msg
	integer size
	return
		userdata queue
		integer type
		integer fd
		string msg | lightuserdata/integer
 */
static int
lfilter(lua_State *L) {
	struct skynet_socket_message *message = lua_touserdata(L,2);
	int size = luaL_checkinteger(L,3);
	char * buffer = message->buffer;
	if (buffer == NULL) {
		buffer = (char *)(message+1);
		size -= sizeof(*message);
	} else {
		size = -1;
	}

	lua_settop(L, 1);

	switch(message->type) {
	case SKYNET_SOCKET_TYPE_DATA:
		// ignore listen id (message->id)
		assert(size == -1);	// never padding string
		return filter_data(L, message->id, (uint8_t *)buffer, message->ud);
	case SKYNET_SOCKET_TYPE_CONNECT:
		// ignore listen fd connect
		return 1;
	case SKYNET_SOCKET_TYPE_CLOSE:
		// no more data in fd (message->id)
		close_uncomplete(L, message->id);
		lua_pushvalue(L, lua_upvalueindex(TYPE_CLOSE));
		lua_pushinteger(L, message->id);
		return 3;
	case SKYNET_SOCKET_TYPE_ACCEPT:
		lua_pushvalue(L, lua_upvalueindex(TYPE_OPEN));
		// ignore listen id (message->id);
		lua_pushinteger(L, message->ud);
		pushstring(L, buffer, size);
		return 4;
	case SKYNET_SOCKET_TYPE_ERROR:
		// no more data in fd (message->id)
		close_uncomplete(L, message->id);
		lua_pushvalue(L, lua_upvalueindex(TYPE_ERROR));
		lua_pushinteger(L, message->id);
		pushstring(L, buffer, size);
		return 4;
	case SKYNET_SOCKET_TYPE_WARNING:
		lua_pushvalue(L, lua_upvalueindex(TYPE_WARNING));
		lua_pushinteger(L, message->id);
		lua_pushinteger(L, message->ud);
		return 4;
	default:
		// never get here
		return 1;
	}
}

/*
	userdata queue
	return
		integer fd
		lightuserdata msg
		integer size
 */
static int
lpop(lua_State *L) {
	struct queue * q = lua_touserdata(L, 1);
	if (q == NULL || q->head == q->tail)
		return 0;
	struct netpack *np = &q->queue[q->head];
	if (++q->head >= q->cap) {
		q->head = 0;
	}
	lua_pushinteger(L, np->id);
	lua_pushlightuserdata(L, np->buffer);
	lua_pushinteger(L, np->size);
	lua_pushinteger(L, np->flag);
	lua_pushinteger(L, np->cmd);
	lua_pushinteger(L, np->version);
	lua_pushinteger(L, np->subversion);

	return 7;
}

static int mypack(void * temp_buffer, int8_t flag, uint16_t cmd, int8_t version, int8_t subversion, uint32_t seq, uint16_t length, void * buffer) {
	if (flag == 1) {
		uint8_t code = 0;
		if (length > 0) {
			memcpy(temp_buffer + MY_HEADER_SIZE, buffer, length);
			code = by_pack_encrypt(temp_buffer, MY_HEADER_SIZE, length);
		}
        memcpy(temp_buffer + 0, "MY", 2);
        memcpy(temp_buffer + 2, &cmd, sizeof (uint16_t));
        memcpy(temp_buffer + 4, &version, sizeof (uint8_t));
        memcpy(temp_buffer + 5, &subversion, sizeof (uint8_t));
        memcpy(temp_buffer + 6, &length, sizeof (uint16_t));
        memcpy(temp_buffer + 8, &code, sizeof (uint8_t));
        memcpy(temp_buffer + 9, &seq, sizeof (uint32_t));
        return 1;
	} else {
		memcpy(temp_buffer + 0, &length, sizeof (uint16_t));
		memcpy(temp_buffer + 2, buffer, length);
		return 0;
	}
}

static int 
lmypack(lua_State *L) {
	int8_t flag = luaL_checkinteger(L, 1);
	uint16_t cmd = luaL_checkinteger(L, 2);
	uint16_t length = luaL_checkinteger(L, 3);
	//const char * buffer = (const char *)lua_tostring(L, 4);
	char * buffer;
	size_t len;
	if (lua_islightuserdata(L, 4)) {
		buffer = lua_touserdata(L, 4);
		len = luaL_checkinteger(L, 3);
	} else {
		buffer = (void *)luaL_checklstring(L, 4, &len);
	}
	
	if (length > 0) {
		if (flag == 1) {
			void * temp_buffer = skynet_malloc(length + MY_HEADER_SIZE);
			mypack(temp_buffer, 1, cmd, 2, 1, 0, length, buffer);
			lua_pushlightuserdata(L, temp_buffer);
			lua_pushinteger(L, length + MY_HEADER_SIZE);
			return 2;
		}else {
			void * temp_buffer = skynet_malloc(length + 2);
			memcpy(temp_buffer + 0, &length, sizeof (uint16_t));
			memcpy(temp_buffer + 2, buffer, length);
			lua_pushlightuserdata(L, temp_buffer);
			lua_pushinteger(L, length + 2);
			return 2;
		}
	} else {
		lua_pushlightuserdata(L, &len);
		lua_pushinteger(L, 0);
		return 2;
	}
}


/*
	string msg | lightuserdata/integer

	lightuserdata/integer
 */

static const char *
tolstring(lua_State *L, size_t *sz, int index) {
	const char * ptr;
	if (lua_isuserdata(L,index)) {
		ptr = (const char *)lua_touserdata(L,index);
		*sz = (size_t)luaL_checkinteger(L, index+1);
	} else {
		ptr = luaL_checklstring(L, index, sz);
	}
	return ptr;
}

static inline void
write_size(uint8_t * buffer, int len) {
	buffer[0] = (len >> 8) & 0xff;
	buffer[1] = len & 0xff;
}

static int
lpack(lua_State *L) {
	size_t len;
	const char * ptr = tolstring(L, &len, 1);
	if (len >= 0x10000) {
		return luaL_error(L, "Invalid size (too long) of data : %d", (int)len);
	}

	uint8_t * buffer = skynet_malloc(len + 2);
	write_size(buffer, len);
	memcpy(buffer+2, ptr, len);

	lua_pushlightuserdata(L, buffer);
	lua_pushinteger(L, len + 2);

	return 2;
}

static int
ltostring(lua_State *L) {
	void * ptr = lua_touserdata(L, 1);
	int size = luaL_checkinteger(L, 2);
	if (ptr == NULL) {
		lua_pushliteral(L, "");
	} else {
		lua_pushlstring(L, (const char *)ptr, size);
		skynet_free(ptr);
	}
	return 1;
}

LUAMOD_API int
luaopen_mypack_lxt(lua_State *L) {
	luaL_checkversion(L);
	luaL_Reg l[] = {
		{ "pop", lpop },
		{ "pack", lpack },
		{ "mypack", lmypack },
		{ "clear", lclear },
		{ "tostring", ltostring },
		{ NULL, NULL },
	};
	luaL_newlib(L,l);

	// the order is same with macros : TYPE_* (defined top)
	lua_pushliteral(L, "data");
	lua_pushliteral(L, "more");
	lua_pushliteral(L, "error");
	lua_pushliteral(L, "open");
	lua_pushliteral(L, "close");
	lua_pushliteral(L, "warning");

	lua_pushcclosure(L, lfilter, 6);
	lua_setfield(L, -2, "filter");

	return 1;
}
