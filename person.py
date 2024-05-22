#!/usr/bin/env python3

import libsig
import logging

class Person:
    def __init__(self, name, log_level='DEBUG'):
        self.name = name
        self.logging = logging
        self.logging.basicConfig(level=log_level)

        self.dh = libsig.GENERATE_DH()


    def get_public_key(self):
        return self.dh.get_public_key()

    def get_dh_public_key(self):
        return self.state.DHs.get_public_key()

    def get_sk(self, peer_pub_key):
        return self.dh.get_derived_key(peer_pub_key)

    def alice_init(self, SK, dh_pub_key):
        """
        """
        self.state = libsig.DHRatchet.init(State(self.name), SK, dh_pub_key)

    def bob_init(self, SK):
        """
        person2.rt_init(SK, None)
        person1.rt_init(SK, person2.get_dh_public_key())
        """
        self.state = libsig.DHRatchet.init(State(self.name), SK, None)

    def send_message(self, message, AD):
        self.state.CKs, mk = libsig.KDF_CK(self.state.CKs)
        header = libsig.HEADER(self.state.DHs, self.state.PN, self.state.Ns)
        self.state.Ns += 1
        self.state.report_status()
        return header, libsig.ENCRYPT(mk, message.encode(), 
                                      libsig.CONCAT(AD, header))

    def try_skip_message_keys(self, header, ciphertext, AD):
        if (header.DH.get_public_key(), header.N) in self.state.MKSKIPPED:
            mk = self.state.MKSKIPPED[header.DH.get_public_key(), header.N]
            del self.state.MKSKIPPED[header.DH.get_public_key(), header.N]
            return libsig.DECRYPT(mk, ciphertext, libsig.CONCAT(AD, header))

    def skip_message_keys(self, until):
        if self.state.CKr:
            while self.state.Nr < until:
                self.state.CKr, mk = libsig.KDF_CK(self.state.CKr)
                self.state.MKSKIPPED[self.state.DHr, self.state.Nr] = mk
                self.state.Nr += 1

    def read_message(self, header, ciphertext, AD):
        plaintext = self.try_skip_message_keys(header, ciphertext, AD)
        if plaintext:
            self.state.report_status()
            return plaintext

        if header.DH.get_public_key() != self.state.DHr:
            self.skip_message_keys(header.PN)
            dh_ratchet = libsig.DHRatchet(self.state, header)
            self.state = dh_ratchet.get_state()

        self.skip_message_keys(header.N)
        self.state.CKr, mk = libsig.KDF_CK(self.state.CKr)
        self.state.Nr += 1

        try:
            plaintext = libsig.DECRYPT(mk, ciphertext, libsig.CONCAT(AD, header))
            self.state.report_status()
            return plaintext
        except ValueError as error:
            logging.error("%s: !!(KERNEL PANIC) - failed to verify cipher text", 
                          self.name)
            raise error
        except Exception as error:
            raise error

