#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "lua.h"
#include "lauxlib.h"

#define LUA_PACKETHANDLE "mypacket_metatable"
#define PACKET_MAX_BUFFER    1024*16
typedef unsigned char BYTE;

typedef struct{
    int owner;
    const char * read_buffer;
    char * write_buffer;
    int buffer_pos;
    int packet_size;
} packet_t;


static int 
_free(lua_State* L) {
	packet_t** userdata = (packet_t**)lua_touserdata(L, -1);
	if( *userdata ) {
		free(*userdata);
	}
	return 0;
}

static packet_t * 
check_packet(lua_State* L) {
	packet_t ** userdata = luaL_checkudata(L, 1, LUA_PACKETHANDLE);
	return *userdata;
}

int _new(lua_State* L) {
	lua_settop(L, 3);
	packet_t * self = (packet_t*)malloc(sizeof(packet_t));
    int len;
    size_t temp;
    
    if (lua_type(L, 1) == LUA_TSTRING) {
        self->read_buffer = lua_tolstring(L, 1, &temp);
        len = (int)temp;
        if (len > PACKET_MAX_BUFFER) len = PACKET_MAX_BUFFER;
        self->owner = 0;
    } else if (lua_isuserdata(L, 1)) {
        self->read_buffer = lua_touserdata(L, 1);
        len = (int)luaL_checkinteger(L, 2);
        if (len > PACKET_MAX_BUFFER) len = PACKET_MAX_BUFFER;
        self->owner = lua_toboolean(L, 3);
    } else {
        len = (int)luaL_checkinteger(L, 1);
        if (len > PACKET_MAX_BUFFER) len = PACKET_MAX_BUFFER;
        self->write_buffer = (char *)malloc(len);
        self->owner = 1;
    }
    self->buffer_pos = 0;
    self->packet_size = len;
    
	packet_t ** userdata = (packet_t**)lua_newuserdata(L, sizeof(packet_t*));
	*userdata = self;
	luaL_getmetatable(L, LUA_PACKETHANDLE);
	lua_setmetatable(L, -2);
	return 1;
}

static int 
_gc(lua_State *L) {
    packet_t *self = check_packet(L);
    if (self->owner && self->write_buffer) {
        free(self->write_buffer);
        self->packet_size = 0;
        self->buffer_pos = 0;
    }
    return 0;
}

static int 
_length(lua_State *L) {
    packet_t *self = check_packet(L);
    lua_pushinteger(L, self->buffer_pos);
    return 1;
}

static int 
_packet_size(lua_State *L) {
    packet_t *self = check_packet(L);
    lua_pushinteger(L, self->packet_size);
	return 1;
}

static packet_t * 
check_write_packet(lua_State *L, int len) {
    packet_t *self = check_packet(L);
    if (self->buffer_pos < 0 || ((self->buffer_pos + len) > self->packet_size)) {
        luaL_error(L, "no more data, owner=%d", self->owner);
    }        
    return self;
}

static bool 
_write(packet_t *self, const char * in, int len) {
	if (self->buffer_pos < 0 || ((self->buffer_pos + len) > self->packet_size)) {
		return false;
	}
	memcpy(self->write_buffer + self->buffer_pos, in, len);
	self->buffer_pos += len;
	
	return true;
}

static int 
_write_byte(lua_State *L) {
    lua_settop(L, 2);
    packet_t *self = check_write_packet(L, sizeof(BYTE));
    BYTE in = (BYTE)luaL_checkinteger(L, 2);
    _write(self, (char *)&in, sizeof(BYTE));
    return 0;
}

static int 
_write_short(lua_State *L) {    
    lua_settop(L, 2);
    packet_t *self = check_write_packet(L, sizeof(short));
    short in = (short)luaL_checkinteger(L, 2);
    _write(self, (char *)&in, sizeof(short));    
    return 0;
}

static int 
_write_int(lua_State *L) {
    lua_settop(L, 2);
    packet_t *self = check_write_packet(L, sizeof(int));
    int in =  (int)luaL_checkinteger(L, 2);
    _write(self, (char *)&in, sizeof(int)); 
    return 0;
}

static int 
_write_int64(lua_State *L) {
    lua_settop(L, 2);
    packet_t *self = check_write_packet(L, sizeof(uint64_t));
    uint64_t in = (uint64_t)luaL_checkinteger(L, 2);
    _write(self, (char *)&in, sizeof(uint64_t));
    return 0;
}

static int 
_write_float(lua_State *L) {
    lua_settop(L, 2);
    packet_t *self = check_write_packet(L, sizeof(float));
    float in = (float)luaL_checkinteger(L, 2);
    _write(self, (char *)&in, sizeof(float));
    return 0;
}

static int 
_write_float64(lua_State *L) {
    lua_settop(L, 2);
    packet_t *self = check_write_packet(L, sizeof(double));
    double in = (double)luaL_checkinteger(L, 2);
    _write(self, (char *)&in, sizeof(double));
    return 0;
}

static int 
_write_ulong(lua_State *L) {
    lua_settop(L, 2);
    packet_t *self = check_write_packet(L, sizeof(unsigned long));
    unsigned long in = (unsigned long)luaL_checkinteger(L, 2);
    _write(self, (char *)&in, sizeof(unsigned long));
    return 0;
}

static int 
_write_zero(lua_State *L) {
	packet_t *self = check_write_packet(L, sizeof(char));
	memset(self->write_buffer+self->buffer_pos, '\0', sizeof(char));
	self->buffer_pos++;	
    return 0;
}

static int 
_write_bytes(lua_State *L) {
   lua_settop(L, 3);
    size_t len;
    const void *data;
    if (lua_islightuserdata(L, 2)) {
        data = lua_touserdata(L, 2);
        len = luaL_checkinteger(L, 3);
    } else {
        data = (void *)luaL_checklstring(L, 2, &len);
    }
    
    if (len == 0) {
        return 0;
    }
    
    packet_t *self = check_write_packet(L, len+sizeof(int));
    int in = (int)len + 1;
    _write(self, (char *)&in, sizeof(int));
    _write(self, (char *)data, len);
    _write_zero(L);
    return 0;
}

static int 
_write_string(lua_State *L) {
    _write_bytes(L);
    return 0;
}

static packet_t * 
check_read_packet(lua_State *L, int len) {
    packet_t *self = check_packet(L);
    
    if ((len + self->buffer_pos) > self->packet_size) {
        luaL_error(L, "no more data");
    }
    return self;
}

static bool 
_read(packet_t *self, char * out, int len) {
	if ((len + self->buffer_pos) > self->packet_size) {
		return false;
	}
	memcpy(out, self->read_buffer + self->buffer_pos, len);
	self->buffer_pos += len;
	return true;
}

static int 
_read_byte(lua_State *L) {
    packet_t *self = check_read_packet(L, sizeof(BYTE));
    BYTE out = -1;
    _read(self, (char *)&out, sizeof(BYTE));
    lua_pushnumber(L, out);
    return 1;
}

static int 
_read_short(lua_State *L) {
    packet_t *self = check_read_packet(L, sizeof(short));
    short out = - 1;
    _read(self, (char *)&out, sizeof(short));
    lua_pushnumber(L, out);
    return 1;
}

static int 
_read_int(lua_State *L) {
    packet_t *self = check_read_packet(L, sizeof(int));
    int out = - 1;
    _read(self, (char *)&out, sizeof(int));
    lua_pushnumber(L, out);
    return 1;
}

static int 
_read_int64(lua_State *L) {
    packet_t *self = check_read_packet(L, sizeof(int64_t));
    int64_t out = - 1;
    _read(self, (char *)&out, sizeof(int64_t));
    lua_pushnumber(L, out);
    return 1;
}

static int 
_read_float(lua_State *L) {
    packet_t *self = check_read_packet(L, sizeof(float));
    float out = - 1;
    _read(self, (char *)&out, sizeof(float));
    lua_pushnumber(L, out);
    return 1;
}

static int 
_read_float64(lua_State *L) {
    packet_t *self = check_read_packet(L, sizeof(double));
    double out = - 1;
    _read(self, (char *)&out, sizeof(double));
    lua_pushnumber(L, out);
    return 1;
}

static int 
_read_ulong(lua_State *L) {
    packet_t *self = check_read_packet(L, sizeof(unsigned long));
    unsigned long out = - 1;
    _read(self, (char *)&out, sizeof(unsigned long));
    lua_pushnumber(L, out);
    return 1;
}

static int 
_read_bytes(lua_State *L) {
    lua_settop(L, 2);
    packet_t *self = check_read_packet(L, sizeof(int));
    int maxlen = (int)luaL_checkinteger(L, 2);
    
	int len = - 1;
    _read(self, (char *)&len, sizeof(int));
    
	if (len == -1) {
		lua_pushstring(L, NULL);
	} else {
		if (len > maxlen) len = maxlen;
		char * out;
		_read(self, (char *)&out, len);
    	lua_pushlstring(L, out, len);
    }
    return 1;
}

static int 
_read_string(lua_State *L) {
	packet_t *self = check_read_packet(L, sizeof(int));
	int len = - 1;
    _read(self, (char *)&len, sizeof(int));
	if (len == -1) {
		lua_pushstring(L, NULL);
		return 1;
	} else {
		len = len - 1;
		char * out = (char *)malloc(len);;
		_read(self, out, len);
		lua_pushlstring(L, out, len);
		return 1;
    }
}


static int 
_pack(lua_State *L) {
    packet_t *self = check_packet(L);
    lua_pushlightuserdata(L, self->write_buffer);
    lua_pushinteger(L, self->buffer_pos);
    self->write_buffer = NULL;
    self->read_buffer = NULL;
    return 2;
}

int luaopen_mypacket_lxt(lua_State *L) {
luaL_checkversion(L);
    
    luaL_Reg l[] = {
        {"new", _new},
        {"__gc", _gc},
        {"__len", _length},
        {"packet_size", _packet_size},
        {"write_byte", _write_byte},
        {"write_short", _write_short},
        {"write_int", _write_int},
        {"write_int64", _write_int64},
        {"write_bytes", _write_bytes}, 
        {"write_string", _write_string},
        {"write_zero", _write_zero},
        {"write_ulong", _write_ulong},
        {"write_float64", _write_float64},
        {"write_float", _write_float},
        {"read_byte", _read_byte},
        {"read_short", _read_short},
        {"read_int", _read_int},
        {"read_int64", _read_int64},
        {"read_bytes", _read_bytes}, 
        {"read_string", _read_string},
        {"read_ulong", _read_ulong},
        {"read_float64", _read_float64},
        {"read_float", _read_float},        
        {"pack", _pack},
        {"free", _free},
	  	{NULL, NULL}
    };
    
    luaL_newlib(L, l);
	luaL_newmetatable(L, LUA_PACKETHANDLE);
    luaL_setfuncs(L, l, 0);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");		
    return 1;
}
