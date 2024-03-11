#!/usr/bin/env python3
import logging
import sys
from person import Person
from libsig import HEADER

def dh_handshake(person1, person2):
    # get Alice public key to send to Bob
    person1_pub_key = person1.get_public_key()

    # Bob returns his public key initiazlied with Alice's public key
    person2.ini_with_public_key(person1_pub_key)
    person2_pub_key = person2.get_public_key()

    # handshake complete
    person1.ini_with_public_key(person2_pub_key)

    person1_sk = person1.get_sk()
    person2_sk = person2.get_sk()
    assert(person1_sk == person2_sk)

    return person1_sk

def ratchet_init(SK, person1, person2):
    person2.rt_init(SK, None)
    person1.rt_init(SK, person2.get_dh_public_key())

    return person1, person2

def send_message(message, person1, person2):
    """Observations:
    - PN keeps increasing, though it should be Ns -> Why?
    """
    def person1_message():
        # Full Cycle
        AD = "SEND_MSG_ALICE"
        header, cipher_txt_person1 = person1.send_message(message, AD)
        plaintext_person1 = person2.read_message(header, cipher_txt_person1, AD)
        assert(plaintext_person1.decode("utf-8") == message)
        logging.info("%d:%s: says decrypted: %s", 2, person2.name, plaintext_person1)
        return person1, person2

    def person2_message():
        # Full Cycle
        AD = "SEND_MSG_BOB"
        header, cipher_txt_person2 = person2.send_message(message, AD)
        plaintext_person2 = person1.read_message(header, cipher_txt_person2, AD)
        assert(plaintext_person2.decode("utf-8") == message)
        logging.info("%d:%s: says decrypted: %s", 2, person2.name, plaintext_person2)
        return person1, person2

    def person1_message_nr():
        # Full Cycle
        AD = "SEND_MSG_ALICE"
        header, cipher_txt_person1 = person1.send_message(message, AD)
        print(header.DH.get_public_key(), header.N)
        header1, cipher_txt_person1_1 = person1.send_message(message, AD)

        plaintext_person1_1 = person2.read_message(header1, cipher_txt_person1_1, AD)
        assert(plaintext_person1_1.decode("utf-8") == message)
        logging.info("%d:%s: says decrypted_nr: %s", 2, person2.name, 
                     plaintext_person1_1)

        plaintext_person1 = person2.read_message(header, cipher_txt_person1, AD)
        assert(plaintext_person1.decode("utf-8") == message)
        logging.info("%d:%s: says decrypted_nr: %s", 2, person2.name, 
                     plaintext_person1)

        return person1, person2

    # Because Alice has to message first
    # TODO: implement such that Bob can message first
    person1, person2 = person1_message()

    logging.info("\n<=======INIT DONE==============>\n")

    person1_message_nr()
    fn_persons = [person1_message, person2_message]

    import random
    for i in range(10):
        """
        """
        r_int = random.randint(0, 1)
        person1, person2 = fn_persons[r_int]()


def main():
    log_level = 'DEBUG'
    if len(sys.argv) > 1:
        log_level = sys.argv[1]

    logging.basicConfig(level=log_level)

    Alice = Person("Alice")
    Bob = Person("Bob")

    # Alice wants to send a message to Bob. 
    # Since everything is None, Alice does the due-deligence with Bob
    # They both get their SK and Alice gets Bob to turn the Ratchet
    # Then hands over that PubKey for that Ratchet

    # step 1: we both need a shared secret (SK)
    SK = dh_handshake(Alice, Bob)

    # step 2: get bob's ratchet pub key
    Alice, Bob = ratchet_init(SK, Alice, Bob)

    # step 3: Alice should now send a message
    message = "Hello world"
    send_message(message, Alice, Bob)


if __name__ == "__main__":
    main()
