#include <stdlib.h>
#include <string.h>
#include "mqtt.h"
#include "pack.h"

static size_t unpack_mqtt_connect(const unsigned char *,
                                  union mqtt_header *,
                                  union mqtt_packet *);
static size_t unpack_mqtt_publish(const unsigned char *,
                                  union mqtt_header *,
                                  union mqtt_packet *);
static size_t unpack_mqtt_subscribe(const unsigned char *,
                                    union mqtt_header *,
                                    union mqtt_packet *);
static size_t unpack_mqtt_unsubscribe(const unsigned char *,
                                      union mqtt_header *,
                                      union mqtt_packet *);
static size_t unpack_mqtt_ack(const unsigned char *,
                              union mqtt_header *,
                              union mqtt_packet *);
static unsigned char *pack_mqtt_header(const union mqtt_header *);
static unsigned char *pack_mqtt_ack(const union mqtt_packet *);
static unsigned char *pack_mqtt_connack(const union mqtt_packet *);
static unsigned char *pack_mqtt_suback(const union mqtt_packet *);
static unsigned char *pack_mqtt_publish(const union mqtt_packet *);

typedef size_t mqtt_unpack_handler(const unsigned *, union mqtt_header *, union mqtt_packet *);

/*
*   MATT v3.1.1 standard, Remaining lenght field on the fixed header can
*   be at most 4 bytes.
*/
static const int MAX_LEN_BYTES = 4;

/*
*   Encode Remaining Lenght on a MQTT Packet header, compromised of Variable
*   Header and Payload if present. It does not take into account
*   the bytes required to store itself. Refer to MQTT v3.1.1 algo
*   for the implementation.
*/
int mqtt_encode_lenght(unsigned char *buf, size_t len)
{
    int bytes = 0;
    do {
        if (bytes + 1 > MAX_LEN_BYTES)
            return bytes;
        short d = len % 128;
        len /= 128;
        // if there are more digits to encode, set the top bit of this digit
        if (len > 0)
            d |= 128;
        buf[bytes++] = d;
    } while (len > 0);
    return bytes;
}

/*
 * Decode Remaining Length comprised of Variable Header and Payload if
 * present. It does not take into account the bytes for storing length. Refer
 * to MQTT v3.1.1 algorithm for the implementation suggestion.
 *
 * TODO Handle case where multiplier > 128 * 128 * 128
 */
unsigned long long mqtt_decode_length(const unsigned char **buf)
{
    char c;
    int multiplier = 1;
    unsigned long long value = 0LL;
    do {
        c = **buf;
        value += (c & 127) * multiplier;
        multiplier *= 128;
        (*buf)++;
    } while ((c & 128) != 0);
    return value;
}

/*
 *   MQTT unpacking functions
 */
static size_t unpack_mqtt_connect(const unsigned char *buf, union mqtt_header *header, union mqtt_packet *packet)
{
    struct mqtt_connect connect = { .header = *header };
    packet->connect = connect;
    const unsigned char *init = buf;
    /*
     * Second byte of the fixed header, contains the length of remaining bytes
     * of the connect packet
     */
    size_t len = mqtt_decode_length(&buf);
    /*
     *   For now we ignore checks on protocol name and reserved bits, just skip 
     *   to the 8th byte
     */
    buf = init + 8;
    /*  Read variable header byte flags     */
    packet->connect.byte = unpack_u8((const uint8_t **) &buf);
    /*  Read keepalive MSB and LSB (2 bytes word)   */
    packet->connect.payload.keepalive = unpack_u16((const uint8_t **) &buf);
    /*  Read CID length (2 byte word)           */
    uint16_t cid_len = unpack_u16((const uint8_t **) &buf);
    /*  Read the client id  */
    if (cid_len > 0)
    {
        packet->connect.payload.client_id = malloc(cid_len + 1);
        unpack_bytes((const uint8_t **) &buf, cid_len, packet->connect.payload.client_id);
    }
    /*  Read the will topic and message if will is set on floags    */
    if (packet->connect.bits.will == 1)
    {
        unpack_string16(&buf, &packet->connect.payload.will_topic);
        unpack_string16(&buf, &packet->connect.payload.will_message);
    }
    /*  Read the username if username flag is set   */
    if (packet->connect.bits.username == 1)
        unpack_string16(&buf, &packet->connect.payload.username);
    /*  Read the password if password flag is set   */
    if (packet->connect.bits.password == 1)
        unpack_string16(&buf, &packet->connect.payload.password);
    return len;
}

static size_t unpack_mqtt_publish(const unsigned char *buf, union mqtt_header *header,union mqtt_packet *packet) 
{
    struct mqtt_publish publish = { .header = *header };
    packet->publish = publish;
    /*
     * Second byte of the fixed header, contains the length of remaining bytes
     * of the connect packet
     */
    size_t len = mqtt_decode_length(&buf);
    /* Read topic length and topic of the soon-to-be-published message */
    packet->publish.topiclen = unpack_string16(&buf, &packet->publish.topic);
    uint16_t message_len = len;
    /* Read packet id */
    if (publish.header.bits.qos > AT_MOST_ONCE) {
        packet->publish.pkt_id = unpack_u16((const uint8_t **) &buf);
        message_len -= sizeof(uint16_t);
    }
    /*
     * Message len is calculated subtracting the length of the variable header
     * from the Remaining Length field that is in the Fixed Header
     */
    message_len -= (sizeof(uint16_t) + packet->publish.topiclen);
    packet->publish.payloadlen = message_len;
    packet->publish.payload = malloc(message_len + 1);
    unpack_bytes((const uint8_t **) &buf, message_len, packet->publish.payload);
    return len;
}

static size_t unpack_mqtt_subscribe(const unsigned char *buf, union mqtt_header *header, union mqtt_packet *packet)
{
    struct mqtt_subscribe subscribe = { .header = *header };
    /*
     * Second byte of the fixed header, contains the length of remaining bytes
     * of the connect packet
     */
    size_t len = mqtt_decode_lenght(&buf);
    size_t remaining_bytes = len;
    /* Read packet id */
    subscribe.pkt_id = unpack_u16((const uint8_t **) &buf);
    remaining_bytes -= sizeof(uint16_t);
    /*
     * Read in a loop all remaining bytes specified by len of the Fixed Header.
     * From now on the payload consists of 3-tuples formed by:
     *  - topic length
     *  - topic filter (string)
     *  - qos
     */
    int i = 0;
    while (remaining_bytes > 0)
    {
        /* Read length bytes of the first topic filter */
        remaining_bytes -= sizeof(uint16_t);
        /* We have to make room for additional incoming tuples */
        subscribe.tuples = realloc(subscribe.tuples, (i+1)*sizeof(*subscribe.tuples));
        subscribe.tuples[i].topic_len = unpack_string16(&buf, &subscribe.tuples[i].topic);
        len -= sizeof(uint8_t);
        i++;
    }
    subscribe.tubles_len = i;
    packet->subscribe = subscribe;
    return len;
}

static size_t unpack_mqtt_unsubscribe(const unsigned char *buf,
                                      union mqtt_header *hdr,
                                      union mqtt_packet *pkt) {
    struct mqtt_unsubscribe unsubscribe = { .header = *hdr };
    /*
     * Second byte of the fixed header, contains the length of remaining bytes
     * of the connect packet
     */
    size_t len = mqtt_decode_length(&buf);
    size_t remaining_bytes = len;
    /* Read packet id */
    unsubscribe.pkt_id = unpack_u16((const uint8_t **) &buf);
    remaining_bytes -= sizeof(uint16_t);
    /*
     * Read in a loop all remaining bytes specified by len of the Fixed Header.
     * From now on the payload consists of 2-tuples formed by:
     *  - topic length
     *  - topic filter (string)
     */
    int i = 0;
    while (remaining_bytes > 0) {
        /* Read length bytes of the first topic filter */
        remaining_bytes -= sizeof(uint16_t);
        /* We have to make room for additional incoming tuples */
        unsubscribe.tuples = realloc(unsubscribe.tuples,
                                     (i+1) * sizeof(*unsubscribe.tuples));
        unsubscribe.tuples[i].topic_len =
            unpack_string16(&buf, &unsubscribe.tuples[i].topic);
        remaining_bytes -= unsubscribe.tuples[i].topic_len;
        i++;
    }
    unsubscribe.tuples_len = i;
    pkt->unsubscribe = unsubscribe;
    return len;
}

static size_t unpack_mqtt_ack(const unsigned char *buf, union mqtt_header *hdr, union mqtt_packet *pkt) 
{
    struct mqtt_ack ack = { .header = *hdr };
    /*
     * Second byte of the fixed header, contains the length of remaining bytes
     * of the connect packet
     */
    size_t len = mqtt_decode_length(&buf);
    ack.pkt_id = unpack_u16((const uint8_t **) &buf);
    pkt->ack = ack;
    return len;
}

static mqtt_unpack_handler *unpack_handlers[11] = {
    NULL, 
    unpack_mqtt_connect,
    NULL,
    unpack_mqtt_publish,
    unpack_mqtt_ack,
    unpack_mqtt_ack,
    unpack_mqtt_ack,
    unpack_mqtt_ack,
    unpack_mqtt_subscribe,
    NULL,
    unpack_mqtt_unsubscribe
};

int unpack_mqtt_packet(const char *buf, union mqtt_packet *packet)
{
    int rc = 0;
    /* Read first byte of the fixed header */
    unsigned char type = *buf;
    union mqtt_header header = { .byte = type };
    if (header.bits.type == DISCONNECT 
    || header.bits.type == PINGREQ 
    || header.bits.type == PINGRESP)
    {
        packet->header = header;
    }
    else
    {
        /* Call the appropriate unpack handler based in the message type */
        rc = unpack_handlers[header.bits.type](++buf, &header, packet);
    }
    return rc;
}

/*
 * MQTT packets building functions 
 */

union mqtt_header *mqtt_packet_header(unsigned char byte)
{
    static union mqtt_header header;
    header.byte = byte;
    return &header;
}

struct mqtt_act *mqtt_pack_ack(unsigned char byte, unsigned short pkt_id)
{
    static struct mqtt_ack ack;
    ack.header.byte = byte;
    ack.pkt_id = pkt_id;
    return &ack;
}

struct mqtt_connack *mqtt_packet_connack(unsigned char byte, unsigned char cflags, unsigned char rc)
{
    static struct mqtt_connack connack;
    connack.header.byte = byte;
    connack.byte = cflags;
    connack.rc = rc;
    return &connack;
}

struct mqtt_suback *mqtt_packet_suback(unsigned char byte,
                                       unsigned short pkt_id,
                                       unsigned char *rcs,
                                       unsigned short rcslen)
{
    struct mqtt_suback *suback = malloc(sizeof(*suback));
    suback->header.byte = byte;
    suback->pkt_id = pkt_id;
    suback->rcslen = rcslen;
    suback->rcs = malloc(rcslen);
    memcpy(suback->rcs, rcs, rcslen);
    return suback;
}

struct mqtt_publish *mqtt_packet_publish(unsigned char byte,
                                         unsigned short pkt_id,
                                         size_t topiclen,
                                         unsigned char *topic,
                                         size_t payloadlen,
                                         unsigned char *payload)
{
    struct mqtt_publish *publish = malloc(sizeof(*publish));
    publish->header.byte = byte;
    publish->pkt_id = pkt_id;
    publish->topiclen = topiclen;
    publish->topic = topic;
    publish->payloadlen = payloadlen;
    publish->payload = payload;
    return publish;
}

void mqtt_packet_release(union mqtt_packet *packet, unsigned type)
{
    switch (type)
    {
    case CONNECT:
        free(packet->connect.payload.client_id);
        if (packet->connect.bits.will == 1)
        {
            free(packet->connect.payload.will_topic);
            free(packet->connect.payload.will_message);
        }
        if (packet->connect.bits.username == 1)
            free(packet->connect.payload.username);
        if (packet->connect.bits.password == 1)
            free(packet->connect.payload.password);
        break;
    case SUBSCRIBE:
    case UNSUBSCRIBE:
        for (unsigned i = 0; i < packet->subscribe.tubles_len; i++)
            free(packet->subscribe.tuples[i].topic);
        free(packet->subscribe.tuples);
        break;
    case PUBLISH:
        free(packet->publish.topic);
        free(packet->publish.payload);
        break;
    case SUBACK:
        free(packet->suback.rcs);
        break;
    default:
        break;
    }
}
