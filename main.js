const SEAL = require("node-seal");
var fs = require("fs");
const doit = async (n, m, batch_size) => {
  let start = null;

  // Step 1
  const setup = async () => {
    const seal = await SEAL();
    start = process.hrtime.bigint();
    const schemeType = seal.SchemeType.bfv;
    const securityLevel = seal.SecurityLevel.tc128;
    const polyModulusDegree = 4096;
    const bitSizes = [36, 36, 37];
    const bitSize = 20;
    const encParms = seal.EncryptionParameters(schemeType);
    encParms.setPolyModulusDegree(polyModulusDegree);
    encParms.setCoeffModulus(
      seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes))
    );
    encParms.setPlainModulus(
      seal.PlainModulus.Batching(polyModulusDegree, bitSize)
    );
    const context = seal.Context(
      encParms, // Encryption Parameters
      true,
      securityLevel
    );

    ////////////////////////////
    // Generate keys and shit //
    ////////////////////////////

    return [seal, context];
  };

  const elapsed_time = (n, m, batch_size, n_intersections) => {
    let end = process.hrtime.bigint();
    const elapsedMilliseconds = end - start;
    //console.log("time/ms | n | m | batch_size | number of intersections");
    //console.log(`${elapsedMilliseconds}, ${n}, ${m}, ${batch_size}, ${n_intersections},`);
    start = null;
    s = `${elapsedMilliseconds}, ${n}, ${m}, ${batch_size}, ${n_intersections}`;
    return s;
  };

  const createSets = (n, m) => {
    // Function to generate an array of random numbers
    const generateRandomNumbers = (length) => {
      return Array.from({ length }, () => Math.floor(Math.random() * 10000));
    };

    const firstArray = generateRandomNumbers(n);
    const secondArray = generateRandomNumbers(m);

    //forcing at least 1 intersection
    firstArray[5] = 666;
    secondArray[1] = 666;

    return [firstArray, secondArray];
  };

  ///////////////////////////////
  // Change Length Params Here //
  ///////////////////////////////

  const [alice_array, bob_array] = createSets(n, m);
  const [seal, context] = await setup();

  const keyGenerator = seal.KeyGenerator(context);
  const publicKey = keyGenerator.createPublicKey();
  const secretKey = keyGenerator.secretKey();
  // Create an Evaluator which will allow HE functions to execute
  const evaluator = seal.Evaluator(context);
  // Create a BatchEncoder (only BFV SchemeType)
  const encoder = seal.BatchEncoder(context);
  // Create an Encryptor to encrypt PlainTexts
  const encryptor = seal.Encryptor(context, publicKey);
  // Create a Decryptor to decrypt CipherTexts
  const decryptor = seal.Decryptor(context, secretKey);

  // Step 2
  const alice_encrypt_elements = (alice_array) => {
    // Change type of array to work with SEAL
    const set_alice = Int32Array.from(alice_array);
    // Save the length
    const set_alice_length = set_alice.length;

    // Encode Alice's set
    const set_plaintexts_alice = encoder.encode(set_alice);
    // Encrypt each element in Alice's set
    const set_ciphertexts_alice = encryptor.encrypt(set_plaintexts_alice);
    const set_ciphertexts_alice_string = set_ciphertexts_alice.save();
    return [set_ciphertexts_alice_string, set_alice_length];
  };
  const [set_ciphertexts_alice_string, set_alice_length] =
    alice_encrypt_elements(alice_array);

  // Step 3
  const bob_homomorphic_operations = (
    set_ciphertexts_alice_string,
    set_alice_length,
    elements_bob
  ) => {
    let final_products = [];
    let set_ciphertexts_alice = seal.CipherText();

    set_ciphertexts_alice.load(
      context,
      set_ciphertexts_alice_string,
      evaluator
    );

    // For the optimization, we split Bob's set into multiple subsets, each of size batch_size, for optimization
    const sets_plaintexts_bob = [];
    for (let i = 0; i < elements_bob.length; i += batch_size) {
      const batch = elements_bob.slice(i, i + batch_size);
      sets_plaintexts_bob.push(Int32Array.from(batch));
    }

    sets_plaintexts_bob.forEach((set_plaintexts_bob) => {
      const final_product = seal.CipherText();

      // Homomorphically initialize result to first Alice's element - first Bob's element
      const first_element_bob = Int32Array.from(
        Array(set_alice_length).fill(set_plaintexts_bob[0])
      );
      const first_element_bob_encoded = encoder.encode(first_element_bob);
      evaluator.subPlain(
        set_ciphertexts_alice,
        first_element_bob_encoded,
        final_product
      );

      for (let j = 1; j < set_plaintexts_bob.length; j++) {
        const ith_element_bob = Int32Array.from(
          Array(set_alice_length).fill(set_plaintexts_bob[j])
        );
        const ith_element_bob_encoded = encoder.encode(ith_element_bob);
        const temp = seal.CipherText();
        evaluator.subPlain(
          set_ciphertexts_alice,
          ith_element_bob_encoded,
          temp
        );
        evaluator.multiply(final_product, temp, final_product);
      }

      const final_product_string = final_product.save();
      final_products.push(final_product_string);
    });

    return final_products;
  };
  let final_products = bob_homomorphic_operations(
    set_ciphertexts_alice_string,
    set_alice_length,
    bob_array
  );
  // Step 4
  const alice_decrypt_intersection = (final_products, set_alice_length) => {
    let intersection_indexes = [];

    for (const final_product of final_products) {
      let final_product_ciphertext = seal.CipherText();
      final_product_ciphertext.load(context, final_product);
      const decrypted = decryptor.decrypt(final_product_ciphertext);
      const decoded = encoder.decode(decrypted);

      for (let i = 0; i < set_alice_length; i++) {
        if (decoded[i] == 0) {
          intersection_indexes.push(i);
        }
      }
    }

    return intersection_indexes;
  };

  let intersection_indexes = alice_decrypt_intersection(
    final_products,
    set_alice_length
  );

  let logresult = elapsed_time(n, m, batch_size, intersection_indexes.length);

  const process_intersection_indexes = (
    intersection_indexes,
    aliceArray,
    bobArray
  ) => {
    if (intersection_indexes.length == 0) {
      console.log("no intersection womp womp");
      return;
    }

    let results = [];

    // Loop through intersection indexes to access aliceArray
    for (const index of intersection_indexes) {
      // Check if the index is within bounds
      if (index >= 0 && index < aliceArray.length) {
        let common_item = aliceArray[index];
        if (bobArray.includes(common_item)) {
          results.push(common_item);
        } else {
          console.log(
            "OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT OH SHIT "
          );
        }
      }
    }
    return results;
  };
  process_intersection_indexes(intersection_indexes, alice_array, bob_array);
  return logresult;
};
const log = [];

n = 200;
m = 5;

function logArrayToFile(array) {
  // Convert the array to a string (with each item on a new line)
  const data = array.join("\n");

  // Write the string to log.txt
  fs.writeFile(`log_${n}_${m}.txt`, data, (err) => {
    if (err) {
      console.error("Error writing to file:", err);
    } else {
      console.log("Array logged to log.txt");
    }
  });
}

async function run() {
  for (let i = 0; i < 10; i++) {
    const result = await doit(n, m, 2); // Wait for the promise to resolve
    log.push(result);
  }
  logArrayToFile(log);
}

run(); // Call the async function to start the process
