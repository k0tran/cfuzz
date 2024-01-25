/// This file is autogenerated

#include "time.hpp"

#include <cstdint>
#include <iterator> // for std::size
#include <random>

// Constructor section

struct ConstrData {
    size_t arg_size;
    Time (*fn)(const uint8_t *);
};


Time constr_0(const uint8_t *data) {
    return Time();
}

Time constr_1(const uint8_t *data) {
    size_t size = 0;

    // args
    uint *arg_0 = (uint *)(data + size);
    size += sizeof(uint);

    // call
    return Time(*arg_0);
}


const ConstrData constr_list[] = {

    {
        .arg_size = 0,
        .fn = constr_0
    },

    {
        .arg_size = 0 + sizeof(uint),
        .fn = constr_1
    },
};
constexpr size_t constr_size = std::size(constr_list);

// Method section

struct MethodData {
    size_t arg_size;
    void (*fn)(Time *, const uint8_t *);
};


void method_set(Time *obj, const uint8_t *data) {
    size_t size = 0;

    // args
    uint *arg_0 = (uint *)(data + size);
    size += sizeof(uint);

    // call
    obj->set(*arg_0);
}

void method_zero(Time *obj, const uint8_t *data) {
    // call
    obj->zero();
}

void method_get(Time *obj, const uint8_t *data) {
    // call
    obj->get();
}

void method_secs(Time *obj, const uint8_t *data) {
    // call
    obj->secs();
}

void method_is_zero(Time *obj, const uint8_t *data) {
    // call
    obj->is_zero();
}


const MethodData method_list[] = {

    {
        .arg_size = 0 + sizeof(uint),
        .fn = method_set,
    },

    {
        .arg_size = 0,
        .fn = method_zero,
    },

    {
        .arg_size = 0,
        .fn = method_get,
    },

    {
        .arg_size = 0,
        .fn = method_secs,
    },

    {
        .arg_size = 0,
        .fn = method_is_zero,
    },
};
constexpr size_t method_size = std::size(method_list);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // supported up to 255 constructors and methods

    // empty string
    if (size == 0)
        return 0;

    // get constr id
    size_t args = 0;
    auto c = constr_list[data[args] % constr_size];
    args += 1;

    // check if we have enough space for arguments
    if (args + c.arg_size > size)
        return 0;

    // call constructor
    auto obj = c.fn(data + args);
    args += c.arg_size;

    // check if we have enough space for method id
    if (args >= size)
        return 0;

    // get method
    auto m = method_list[data[args] % method_size];
    args += 1;

    while (args + m.arg_size <= size) {
        // call method
        m.fn(&obj, data + args);
        args += m.arg_size;

        // check if we have space for another method
        if (args >= size)
            return 0;

        // get new method
        m = method_list[data[args] % method_size];
        args += 1;
    }

    return 0;
}

const size_t CHAIN_LIMIT = 10;

extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    if (Size == 0)
        return 0;

    // first we need to know how many there are methods out there
    size_t count = 1, i = constr_list[Data[0] % constr_size].arg_size + 1;
    while (i < Size) {
        i += method_list[Data[i] % method_size].arg_size + 1;
        count += 1;
    }

    // Now choose one of 4 mutations:
    // - Delete call
    // - Add call (place of insertion is chosen above)
    // - Argument mutation
    std::mt19937 rng(Seed);
    size_t target = rng() % count;
    // Skip calls
    size_t j = 0;
    i = constr_list[Data[0] % constr_size].arg_size + 1;
    while (i < Size && j < target) {
        i += method_list[Data[i] % method_size].arg_size + 1;
        j += 1;
    }   
    switch (rng() % 3) {
        case 0: {
            // Shift everything past there
            j = i + method_list[Data[i] % method_size].arg_size + 1;
            while (j < Size) {
                Data[i] = Data[j];
                i++; j++;
            }
            return i + 1;
        }
        case 1: {
            // Can't shift onto constructor
            if (target == 0) i += method_list[Data[i] % method_size].arg_size + 1;
            
            // Choose fitting call
            size_t call_id = rng() % method_size;
            while (method_list[call_id].arg_size + 1 >= Size - MaxSize)
                call_id = rng() % method_size;
            
            // Shift everything out of place
            const size_t shift_amount = method_list[call_id].arg_size + 1; 
            j = Size + shift_amount;

            while (j - shift_amount > i) {
                Data[j] = Data[j - shift_amount];
                j--;
            }

            // Insert call info
            Data[i] = call_id;
            j = i + 1;
            while (j < i + shift_amount) {
                Data[j] = 0;
                j++;
            }
            return Size + shift_amount;
        }
        case 2: {
            // Problem there: we don't know number of arguments
            // TODO: solve this (need to change fuzz generation)
            // But for now...
            j = method_list[Data[i] % method_size].arg_size;
            if (j == 0)
                return Size;
            // Mutate all arguments at once
            LLVMFuzzerMutate(Data + i + 1, j, j);
            return Size;
        }
        default: return Size;
    }
}

// extern "C" size_t LLVMFuzzerCustomCrossOver(
//     const uint8_t *Data1, size_t Size1,
//     const uint8_t *Data2, size_t Size2,
//     uint8_t *Out, size_t MaxOutSize,
//     unsigned int Seed
// ) {
// }
