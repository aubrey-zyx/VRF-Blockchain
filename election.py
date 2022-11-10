import math
import dhvrf
import random


def committee_election(alpha_string, nodes):
    betas = {}
    committee_size = math.ceil(len(nodes) / 2)

    for node in nodes:
        print("# Node {}".format(node))
        test_dict = dict()
        dhvrf.test_dict = test_dict
        sk = random.getrandbits(256).to_bytes(32, 'little')
        _, Y = dhvrf._get_secret_scalar_and_public_key(sk)
        print("SK: {}".format(sk.hex()))
        print("Y: {}\n".format(Y.hex()))

        pi_string = dhvrf.ecvrf_prove(sk, alpha_string)
        print("H: {}\n".format(test_dict['h_sample'].hex()))

        print("Gamma: {}".format(test_dict['gamma_sample'].hex()))
        print("k: {}".format(test_dict['k_sample'].hex()))
        print("c: {}".format(test_dict['c_sample']))
        print("s: {}\n".format(test_dict['s_sample']))
        print("pi_string: {}\n".format(test_dict['pi_string_sample'].hex()))

        beta_string = dhvrf.ecvrf_proof_to_hash(pi_string)
        print("beta_string: {}\n".format(test_dict['beta_string_sample'].hex()))

        valid_result, valid_beta = dhvrf.ecvrf_verify(Y, pi_string, alpha_string)
        print("U: {}".format(test_dict['u_sample'].hex()))
        print("V: {}".format(test_dict['v_sample'].hex()))
        print("c': {}".format(test_dict['cp_sample']))

        if valid_beta != beta_string:
            print("FAIL")
        else:
            print("Node {} PASSED\n".format(node))

        betas[node] = int.from_bytes(beta_string, "big")

    betas_order = sorted(betas.items(), key=lambda x:x[1], reverse=True)
    committee_nodes = [n[0] for n in betas_order[:committee_size]]
    committee_nodes.sort()

    return committee_nodes


def miner_election(alpha_string, committee_nodes):
    committee_betas = {}

    for node in committee_nodes:
        print("# Node {}".format(node))
        test_dict = dict()
        dhvrf.test_dict = test_dict
        sk = random.getrandbits(256).to_bytes(32, 'little')
        _, Y = dhvrf._get_secret_scalar_and_public_key(sk)
        print("SK: {}".format(sk.hex()))
        print("Y: {}\n".format(Y.hex()))

        pi_string = dhvrf.ecvrf_prove(sk, alpha_string)
        print("H: {}\n".format(test_dict['h_sample'].hex()))

        print("Gamma: {}".format(test_dict['gamma_sample'].hex()))
        print("k: {}".format(test_dict['k_sample'].hex()))
        print("c: {}".format(test_dict['c_sample']))
        print("s: {}\n".format(test_dict['s_sample']))
        print("pi_string: {}\n".format(test_dict['pi_string_sample'].hex()))

        beta_string = dhvrf.ecvrf_proof_to_hash(pi_string)
        print("beta_string: {}\n".format(test_dict['beta_string_sample'].hex()))

        valid_result, valid_beta = dhvrf.ecvrf_verify(Y, pi_string, alpha_string)
        print("U: {}".format(test_dict['u_sample'].hex()))
        print("V: {}".format(test_dict['v_sample'].hex()))
        print("c': {}".format(test_dict['cp_sample']))

        if valid_beta != beta_string:
            print("FAIL")
        else:
            print("Node {} PASSED\n".format(node))

        committee_betas[node] = int.from_bytes(beta_string, "big")

    miner = max(committee_betas, key=lambda x:committee_betas[x])

    return miner
