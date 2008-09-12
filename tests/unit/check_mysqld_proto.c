/* Copyright (C) 2007, 2008 MySQL AB */ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "network-mysqld-proto.h"
#include "network-mysqld-binlog.h"
#include "glib-ext.h"

#if GLIB_CHECK_VERSION(2, 16, 0)
#define C(x) x, sizeof(x) - 1

/**
 * Tests for the MySQL Protocol Codec functions
 * @ingroup proto
 */

/*@{*/

/**
 * @test network_mysqld_proto_set_header() and network_mysqld_proto_get_header()
 *
 * how to handle > 16M ?
 */
void test_mysqld_proto_header(void) {
	unsigned char header[4];
	size_t length = 1256;

	g_assert(0 == network_mysqld_proto_set_header(header, length, 0));
	g_assert(length == network_mysqld_proto_get_header(header));
}

/**
 * @test network_mysqld_proto_append_lenenc_int() and network_mysqld_proto_get_lenenc_int()
 *
 */
void test_mysqld_proto_lenenc_int(void) {
	guint64 length, value;
	network_packet packet;

	packet.data = g_string_new(NULL);

	/* we should be able to do more corner case testing
	 *
	 *
	 */
	length = 0; packet.offset = 0;
	g_string_truncate(packet.data, 0);
	g_assert_cmpint(0, ==, network_mysqld_proto_append_lenenc_int(packet.data, length));
	g_assert_cmpint(packet.data->len, ==, 1);
	g_assert_cmpint(0, ==, network_mysqld_proto_get_lenenc_int(&packet, &value));
	g_assert_cmpint(length, ==, value);

	/* 250 is still a one-byte */
	length = 250; packet.offset = 0;
	g_string_truncate(packet.data, 0);
	g_assert_cmpint(0, ==, network_mysqld_proto_append_lenenc_int(packet.data, length));
	g_assert_cmpint(packet.data->len, ==, 1);

	g_assert_cmpint(0, ==, network_mysqld_proto_get_lenenc_int(&packet, &value));
	g_assert_cmpint(length, ==, value);


	/* 251 is the first two-byte */
	length = 251; packet.offset = 0;
	g_string_truncate(packet.data, 0);
	g_assert(0 == network_mysqld_proto_append_lenenc_int(packet.data, length));
	g_assert_cmpint(packet.data->len, ==, 3);
	g_assert_cmpint(0, ==, network_mysqld_proto_get_lenenc_int(&packet, &value));
	g_assert_cmpint(length, ==, value);

	length = 0xffff; packet.offset = 0;
	g_string_truncate(packet.data, 0);
	g_assert(0 == network_mysqld_proto_append_lenenc_int(packet.data, length));
	g_assert_cmpint(packet.data->len, ==, 3);
	g_assert_cmpint(0, ==, network_mysqld_proto_get_lenenc_int(&packet, &value));
	g_assert_cmpint(length, ==, value);

	length = 0x10000; packet.offset = 0;
	g_string_truncate(packet.data, 0);
	g_assert(0 == network_mysqld_proto_append_lenenc_int(packet.data, length));
	g_assert_cmpint(packet.data->len, ==, 4);
	g_assert_cmpint(0, ==, network_mysqld_proto_get_lenenc_int(&packet, &value));
	g_assert_cmpint(length, ==, value);

	g_string_free(packet.data, TRUE);
}

/**
 * @test network_mysqld_proto_append_lenenc_int() and network_mysqld_proto_get_lenenc_int()
 *
 */
void test_mysqld_proto_int(void) {
	guint64 length, value;
	guint8 value8;
	guint16 value16;
	guint32 value32;
	guint64 value64;
	network_packet packet;

	packet.data = g_string_new(NULL);
	/* we should be able to do more corner case testing
	 *
	 *
	 */

	length = 0xfa; packet.offset = 0;
	g_string_truncate(packet.data, 0);
	g_assert(0 == network_mysqld_proto_append_int8(packet.data, length));
	g_assert(packet.data->len == 1);
	g_assert(0 == memcmp(packet.data->str, C("\xfa")));
	g_assert_cmpint(0, ==, network_mysqld_proto_get_int8(&packet, &value8));
	g_assert_cmpint(length, ==, value8);

	length = 0xfffa; packet.offset = 0;
	g_string_truncate(packet.data, 0);
	g_assert(0 == network_mysqld_proto_append_int16(packet.data, length));
	g_assert(packet.data->len == 2);
	g_assert(0 == memcmp(packet.data->str, C("\xfa\xff")));
	g_assert_cmpint(0, ==, network_mysqld_proto_get_int16(&packet, &value16));
	g_assert_cmpint(length, ==, value16);

	length = 0x00fffffa; packet.offset = 0;
	g_string_truncate(packet.data, 0);
	g_assert(0 == network_mysqld_proto_append_int24(packet.data, length));
	g_assert(packet.data->len == 3);
	g_assert(0 == memcmp(packet.data->str, C("\xfa\xff\xff")));
	g_assert_cmpint(0, ==, network_mysqld_proto_get_int24(&packet, &value32));
	g_assert_cmpint(length, ==, value32);

	length = 0xfffffffa; packet.offset = 0;
	g_string_truncate(packet.data, 0);
	g_assert(0 == network_mysqld_proto_append_int32(packet.data, length));
	g_assert(packet.data->len == 4);
	g_assert(0 == memcmp(packet.data->str, C("\xfa\xff\xff\xff")));
	g_assert_cmpint(0, ==, network_mysqld_proto_get_int32(&packet, &value32));
	g_assert_cmpint(length, ==, value32);

	length = 0xfffffffa; packet.offset = 0;
	g_string_truncate(packet.data, 0);
	g_assert(0 == network_mysqld_proto_append_int48(packet.data, length));
	g_assert(packet.data->len == 6);
	g_assert(0 == memcmp(packet.data->str, C("\xfa\xff\xff\xff\x00\x00")));
	g_assert_cmpint(0, ==, network_mysqld_proto_get_int48(&packet, &value64));
	g_assert_cmpint(length, ==, value64);

	length = 0x00fffffffffaUL; packet.offset = 0;
	g_string_truncate(packet.data, 0);
	g_assert(0 == network_mysqld_proto_append_int64(packet.data, length));
	g_assert(packet.data->len == 8);
	g_assert(0 == memcmp(packet.data->str, C("\xfa\xff\xff\xff\xff\x00\x00\x00")));
	g_assert_cmpint(0, ==, network_mysqld_proto_get_int64(&packet, &value64));
	g_assert_cmpuint(length, ==, value64);


	length = 0xfa; packet.offset = 0;
	g_string_truncate(packet.data, 0);
	g_assert_cmpint(0, ==, network_mysqld_proto_append_int8(packet.data, 0xa5));
	g_assert_cmpint(packet.data->len, ==, 1);
	g_assert_cmpint(packet.offset, ==, 0);
	g_assert_cmpint(0, ==, memcmp(packet.data->str, C("\xa5")));

	g_assert_cmpint(0, ==, network_mysqld_proto_append_int8(packet.data, 0x5a));
	g_assert_cmpint(packet.data->len, ==, 2);
	g_assert_cmpint(packet.offset, ==, 0);
	g_assert_cmpint(0, ==, memcmp(packet.data->str, C("\xa5\x5a")));
	g_assert_cmpint(0, ==, network_mysqld_proto_get_int8(&packet, &value8));
	g_assert_cmpint(packet.offset, ==, 1);
	g_assert_cmpint(0xa5, ==, value8);

	g_assert_cmpint(0, ==, network_mysqld_proto_get_int8(&packet, &value8));
	g_assert_cmpint(packet.offset, ==, 2);
	g_assert_cmpint(0x5a, ==, value8);

	g_string_free(packet.data, TRUE);
}
/*@}*/

void test_mysqld_binlog_events(void) {
	/**
	 * decoding the binlog packet
	 *
	 * - http://dev.mysql.com/doc/internals/en/replication-common-header.html
	 *
	 */

	const char rotate_packet[] =
		"/\0\0\1"
		  "\0"        /* OK */
		   "\0\0\0\0" /* timestamp */
		   "\4"       /* ROTATE */
		   "\1\0\0\0" /* server-id */
		   ".\0\0\0"  /* event-size */
		   "\0\0\0\0" /* log-pos */
		   "\0\0"     /* flags */
		   "f\0\0\0\0\0\0\0hostname-bin.000009";

	const char format_packet[] =
		"c\0\0\2"
		  "\0"
		    "F\335\6F" /* timestamp */
		    "\17"      /* FORMAT_DESCRIPTION_EVENT */
		    "\1\0\0\0" /* server-id */
		    "b\0\0\0"  /* event-size */
		    "\0\0\0\0" /* log-pos */
		    "\0\0"     /* flags */
		    "\4\0005.1.16-beta-log\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0238\r\0\10\0\22\0\4\4\4\4\22\0\0O\0\4\32\10\10\10\10"; /* */

	const char query_packet[] = 
		"N\0\0\3"
		  "\0"          
		    "g\255\7F"   /* timestamp */
		    "\2"         /* QUERY_EVENT */
		    "\1\0\0\0"   /* server-id */
		    "M\0\0\0"    /* event-size */
		    "\263\0\0\0" /* log-pos */
		    "\20\0"      /* flags */
		      "\2\0\0\0" /* thread-id */
		      "\0\0\0\0" /* query-time */
		      "\5"       /* str-len of default-db (world) */
		      "\0\0"     /* error-code on master-side */
		        "\32\0"  /* var-size-len (5.0 and later) */
		          "\0"   /* Q_FLAGS2_CODE */
		            "\0@\0\0" /* flags (4byte) */
		          "\1"   /* Q_SQL_MODE_CODE */
		            "\0\0\0\0\0\0\0\0" /* (8byte) */
		          "\6"   /* Q_CATALOG_NZ_CODE */
		            "\3std" /* (4byte) */
		          "\4"   /* Q_CHARSET_CODE */
		            "\10\0\10\0\10\0" /* (6byte) */
		          "world\0"
		          "drop table t1";

	network_mysqld_binlog *binlog;
	network_mysqld_binlog_event *event;
	network_packet *packet;

	/* rotate event */

	binlog = network_mysqld_binlog_new();
	event = network_mysqld_binlog_event_new();
	packet = network_packet_new();
	packet->data = g_string_new(NULL);

	g_string_assign_len(packet->data, C(rotate_packet));

	network_mysqld_proto_skip_network_header(packet);
	network_mysqld_proto_get_binlog_status(packet);
	network_mysqld_proto_get_binlog_event_header(packet, event);

	g_assert_cmpint(event->event_type, ==, ROTATE_EVENT);

	network_mysqld_proto_get_binlog_event(packet, binlog, event);

	g_assert_cmpint(event->event.rotate_event.binlog_pos, ==, 102);
	g_assert_cmpstr(event->event.rotate_event.binlog_file, ==, "hostname-bin.000009");

	g_string_free(packet->data, TRUE);
	network_packet_free(packet);
	network_mysqld_binlog_event_free(event);
	network_mysqld_binlog_free(binlog);

	/* format description */

	binlog = network_mysqld_binlog_new();
	event = network_mysqld_binlog_event_new();
	packet = network_packet_new();
	packet->data = g_string_new(NULL);

	g_string_assign_len(packet->data, C(format_packet));


	network_mysqld_proto_skip_network_header(packet);
	network_mysqld_proto_get_binlog_status(packet);

	network_mysqld_proto_get_binlog_event_header(packet, event);
	g_assert_cmpint(event->event_type, ==, FORMAT_DESCRIPTION_EVENT);

	network_mysqld_proto_get_binlog_event(packet, binlog, event);

	g_string_free(packet->data, TRUE);
	network_packet_free(packet);
	network_mysqld_binlog_event_free(event);
	network_mysqld_binlog_free(binlog);

	/* query */

	binlog = network_mysqld_binlog_new();
	event = network_mysqld_binlog_event_new();
	packet = network_packet_new();
	packet->data = g_string_new(NULL);

	g_string_assign_len(packet->data, C(query_packet));

	network_mysqld_proto_skip_network_header(packet);
	network_mysqld_proto_get_binlog_status(packet);
	network_mysqld_proto_get_binlog_event_header(packet, event);

	g_assert_cmpint(event->event_type, ==, QUERY_EVENT);

	network_mysqld_proto_get_binlog_event(packet, binlog, event);
	g_assert_cmpstr(event->event.query_event.db_name, ==, "world");
	g_assert_cmpstr(event->event.query_event.query, ==, "drop table t1");

	g_string_free(packet->data, TRUE);
	network_packet_free(packet);
	network_mysqld_binlog_event_free(event);
	network_mysqld_binlog_free(binlog);
}

void test_mysqld_proto_gstring_len(void) {
	guint64 length;
	network_packet packet;
	GString *value = g_string_new(NULL);

	packet.data = g_string_new(NULL);

	/* we should be able to do more corner case testing
	 *
	 *
	 */
	length = 0; packet.offset = 0;
	g_string_truncate(packet.data, 0);
	g_assert_cmpint(0, ==, network_mysqld_proto_get_gstring_len(&packet, 0, value));
	g_assert_cmpint(0, ==, value->len);
	g_assert_cmpint(0, !=, network_mysqld_proto_get_gstring_len(&packet, 1, value)); /* empty packet, we should fail */

	g_string_append(packet.data, "012345");
	g_assert_cmpint(0, ==, network_mysqld_proto_get_gstring_len(&packet, 1, value)); /* get one byte ("0"), inc the offset */
	g_assert_cmpint(1, ==, value->len);
	g_assert_cmpstr("0", ==, value->str);
	g_assert_cmpint(0, ==, network_mysqld_proto_get_gstring_len(&packet, 1, value)); /*  */
	g_assert_cmpint(1, ==, value->len);
	g_assert_cmpstr("1", ==, value->str);
	g_assert_cmpint(0, ==, network_mysqld_proto_get_gstring_len(&packet, 4, value)); /*  */
	g_assert_cmpint(4, ==, value->len);
	g_assert_cmpstr("2345", ==, value->str);
	g_assert_cmpint(0, ==, network_mysqld_proto_get_gstring_len(&packet, 0, value)); /* empty fetch, shouldn't cause problems */
	g_assert_cmpint(0, ==, value->len);
	
	g_assert_cmpint(0, !=, network_mysqld_proto_get_gstring_len(&packet, 1, value)); /* get a byte after the end of the packet */
	
	g_assert_cmpint(0, !=, network_mysqld_proto_get_gstring_len(&packet, 0, NULL)); /* empty fetch, shouldn't cause problems */

	g_string_free(packet.data, TRUE);
}

int main(int argc, char **argv) {
	g_test_init(&argc, &argv, NULL);
	g_test_bug_base("http://bugs.mysql.com/");

	g_test_add_func("/core/mysqld-proto-header", test_mysqld_proto_header);
	g_test_add_func("/core/mysqld-proto-lenenc-int", test_mysqld_proto_lenenc_int);
	g_test_add_func("/core/mysqld-proto-int", test_mysqld_proto_int);
	g_test_add_func("/core/mysqld-proto-gstring-len", test_mysqld_proto_gstring_len);

	g_test_add_func("/core/mysqld-proto-binlog-event", test_mysqld_binlog_events);

	return g_test_run();
}
#else
int main() {
	return 77;
}
#endif
