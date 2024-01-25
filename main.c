#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <clang-c/Index.h>

typedef enum CXChildVisitResult CXChildVisitResult;

///////////////////////////// PARSE ARGS /////////////////////////////

typedef struct {
    const char *header_path;
    const char *class_name;
    const char **compiler_args;
    const int compiler_args_n;
} FuzzerArgs;

// If error all FuzzerArgs null
FuzzerArgs parse_args(const int argc, const char **argv) {
    FuzzerArgs args = {0, 0, 0, argc - 3};

    if (argc < 3)
        return args;

    args.header_path = argv[1];
    args.class_name = argv[2];
    args.compiler_args = argv + 3;

    return args;
}

// Print usage and return error code
int usage(const char *program_name) {
    printf("Usage: %s <header> <class> ...args_to_compiler...\n", program_name);
    return 1;
}

// Print error and return error code
int print_error(const char *message) {
    fprintf(stderr, "%s\n", message);
    return 1;
}

///////////////////////////// SETUP CLANG /////////////////////////////

typedef struct {
    CXIndex index;
    CXTranslationUnit translation_unit;
    CXCursor root_cursor;
} ClangData;

// If error index is NULL
ClangData init_clang(const FuzzerArgs *args) {
    ClangData d = {0, 0, 0};

    d.index = clang_createIndex(0, 0);
    d.translation_unit = clang_parseTranslationUnit(
        d.index,
        args->header_path,
        args->compiler_args,
        args->compiler_args_n,
        0,
        0,
        CXTranslationUnit_None
    );

    if (!d.translation_unit) {
        clang_disposeIndex(d.index);
        d.index = 0;
        return d;
    }

    d.root_cursor = clang_getTranslationUnitCursor(d.translation_unit);
    return d;
}

void deinit_clang(ClangData d) {
    clang_disposeTranslationUnit(d.translation_unit);
    clang_disposeIndex(d.index);
}

///////////////////////////// FIND CLASS /////////////////////////////

typedef struct {
    const char *name;
    CXCursor cursor;
} ClangClassInfo;

CXChildVisitResult class_search_visitor(CXCursor cursor, CXCursor parent, CXClientData client_data) {
    if (clang_getCursorKind(cursor) == CXCursor_ClassDecl) {
        CXString current_class = clang_getCursorSpelling(cursor);

        ClangClassInfo *i = (ClangClassInfo * )client_data;
        if (strcmp(clang_getCString(current_class), i->name) == 0) {
            i->cursor = cursor;
            clang_disposeString(current_class);
            return CXChildVisit_Break;
        }

        clang_disposeString(current_class);
    }
    return CXChildVisit_Recurse;
}

// If not found then CXCursor is NULL
CXCursor find_class(ClangData d, const char *class_name) {
    ClangClassInfo i = {class_name, 0};
    clang_visitChildren(d.root_cursor, class_search_visitor, (CXClientData)&i);
    return i.cursor;
}

///////////////////////////// EXTRACT CLASS DATA /////////////////////////////

typedef struct {
    const char **arg_types;
    size_t arg_len;
} ConstructorInfo;

typedef struct {
    const char *name;
    const char **arg_types;
    size_t arg_len;
} MethodInfo;

typedef struct {
    const char *class_name;
    ConstructorInfo *constructors;
    size_t constr_len;
    MethodInfo *methods;
    size_t method_len;
} FuzgenData;

void deinit(FuzgenData *d) {
    for (size_t i = 0; i < 10; ++i) {
        for (size_t j = 0; i < d->constr_len && j < d->constructors[i].arg_len; ++j)
            free(d->constructors[i].arg_types[j]);
        free(d->constructors[i].arg_types);        
    }
    free(d->constructors);
    
    for (size_t i = 0; i < 10; ++i) {
        if (i < d->method_len)
            free(d->methods[i].name);
        for (size_t j = 0; i < d->method_len && j < d->methods[i].arg_len; ++j)
            free(d->methods[i].arg_types[j]);
        free(d->methods[i].arg_types);
    }
    free(d->methods);
}

CXChildVisitResult dump_class_visitor(CXCursor cursor, CXCursor parent, CXClientData client_data) {
    FuzgenData *d = (FuzgenData *)client_data;
    CXString s = clang_getCursorSpelling(parent);
    if (strcmp(d->class_name, clang_getCString(s)))
        return CXChildVisit_Break;
    clang_disposeString(s);

    if (clang_getCursorKind(cursor) == CXCursor_Constructor) {
        ConstructorInfo *cur = d->constructors + d->constr_len;
        d->constr_len++;

        CXType constructorType = clang_getCursorType(cursor);
        cur->arg_len = clang_getNumArgTypes(constructorType);

        for (size_t i = 0; i < cur->arg_len; ++i) {
            cur->arg_types[i] = clang_getCString(clang_getTypeSpelling(clang_getArgType(constructorType, i)));
        }
    } else if (clang_getCursorKind(cursor) == CXCursor_CXXMethod) {
        MethodInfo *cur = d->methods + d->method_len;
        d->method_len++;

        cur->name = clang_getCString(clang_getCursorSpelling(cursor));
        
        CXType methodType = clang_getCursorType(cursor);
        cur->arg_len = clang_getNumArgTypes(methodType);

        for (size_t i = 0; i < cur->arg_len; ++i) {
            cur->arg_types[i] = clang_getCString(clang_getTypeSpelling(clang_getArgType(methodType, i)));
        }
    }
    return CXChildVisit_Continue;
}

FuzgenData from_class(const char *class_name, CXCursor class_cursor) {
    FuzgenData d = {class_name, malloc(10 * sizeof(ConstructorInfo)), 0, malloc(10 * sizeof(MethodInfo)), 0};
    for (size_t i = 0; i < 10; ++i) {
        d.constructors[i].arg_types = malloc(10 * sizeof(const char *));
        d.methods[i].arg_types = malloc(10 * sizeof(const char *));
    }
    clang_visitChildren(class_cursor, dump_class_visitor, (CXClientData)&d);
    return d;
}

///////////////////////////// WRITING FUZZER /////////////////////////////

/// for debug
void print_data(FuzgenData d) {
    puts("--- FUZGEN DATA ---");
    for (size_t i = 0; i < d.constr_len; ++i) {
        puts("Contructor");
        for (size_t j = 0; j < d.constructors[i].arg_len; ++j)
            printf("%s", d.constructors[i].arg_types[j]);
        puts("");
    }
    for (size_t i = 0; i < d.method_len; ++i) {
        printf("Method %s\n", d.methods[i].name);
        for (size_t j = 0; j < d.methods[i].arg_len; ++j)
            printf("%s", d.methods[i].arg_types[j]);
        puts("");
    }
}

/// 1 = header
/// 2 = class name
/// 3 = constructor fns
/// 4 = constructor list
/// 5 = method fns
/// 6 = method list
const char *CORE = 
"/// This file is autogenerated\n\
\n\
#include \"%1$s\"\n\
\n\
#include <cstdint>\n\
#include <iterator> // for std::size\n\
\n\
// Constructor section\n\
\n\
struct ConstrData {\n\
    size_t arg_size;\n\
    %2$s (*fn)(const uint8_t *);\n\
};\n\
\n\
%3$s\n\
\n\
const ConstrData constr_list[] = {\n\
%4$s};\n\
constexpr size_t constr_size = std::size(constr_list);\n\
\n\
// Method section\n\
\n\
struct MethodData {\n\
    size_t arg_size;\n\
    void (*fn)(%2$s *, const uint8_t *);\n\
};\n\
\n\
%5$s\n\
\n\
const MethodData method_list[] = {\n\
%6$s};\n\
constexpr size_t method_size = std::size(method_list);\n\
\n\
\n\
extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\
    // supported up to 255 constructors and methods\n\
\n\
    // empty string\n\
    if (size == 0)\n\
        return 0;\n\
\n\
    // get constr id\n\
    size_t args = 0;\n\
    auto c = constr_list[data[args] %% constr_size];\n\
    args += 1;\n\
\n\
    // check if we have enough space for arguments\n\
    if (args + c.arg_size > size)\n\
        return 0;\n\
\n\
    // call constructor\n\
    auto obj = c.fn(data + args);\n\
    args += c.arg_size;\n\
\n\
    // check if we have enough space for method id\n\
    if (args >= size)\n\
        return 0;\n\
\n\
    // get method\n\
    auto m = method_list[data[args] %% method_size];\n\
    args += 1;\n\
\n\
    while (args + m.arg_size <= size) {\n\
        // call method\n\
        m.fn(&obj, data + args);\n\
        args += m.arg_size;\n\
\n\
        // check if we have space for another method\n\
        if (args >= size)\n\
            return 0;\n\
\n\
        // get new method\n\
        m = method_list[data[args] %% method_size];\n\
        args += 1;\n\
    }\n\
\n\
    return 0;\n\
}\n\
";

/// 1 = class name
/// 2 = i
const char *CONSTR_FN_NOARGS =
"\n\
%1$s constr_%2$d(const uint8_t *data) {\n\
    return %1$s();\n\
}\n\
";

/// 1 = class name
/// 2 = i
/// 3 = args
/// 4 = call args
const char *CONSTR_FN =
"\n\
%1$s constr_%2$d(const uint8_t *data) {\n\
    size_t size = 0;\n\
\n\
    // args\n\
%3$s\n\
    // call\n\
    return %1$s(%4$s);\n\
}\n\
";

/// 1 = type
/// 2 = i
const char *FN_ARG = 
"    %1$s *arg_%2$d = (%1$s *)(data + size);\n\
    size += sizeof(%1$s);\n\
";

/// i
const char *FN_CALL_ARG = "*arg_%d, ";
const char *FN_CALL_ARG_LAST = "*arg_%d";

/// 1 = + sizeof args
/// 2 = i
const char *CONSTR_LIST_ITEM =
"\n\
    {\n\
        .arg_size = 0%1$s,\n\
        .fn = constr_%2$d\n\
    },\n\
";

/// type
const char *SIZE_ARG = " + sizeof(%s)";
const char *SIZE_ARG_LAST = "sizeof(%s)";

/// 1 = method name
/// 2 = class name
const char *METHOD_FN_NOARGS =
"\n\
void method_%1$s(%2$s *obj, const uint8_t *data) {\n\
    // call\n\
    obj->%1$s();\n\
}\n\
";

/// 1 = method name
/// 2 = class name
/// 3 = args
/// 4 = call args
const char *METHOD_FN =
"\n\
void method_%1$s(%2$s *obj, const uint8_t *data) {\n\
    size_t size = 0;\n\
\n\
    // args\n\
%3$s\n\
    // call\n\
    obj->%1$s(%4$s);\n\
}\n\
";

/// 1 = + sizeof args
/// 2 = method name
const char *METHOD_LIST_ITEM =
"\n\
    {\n\
        .arg_size = 0%1$s,\n\
        .fn = method_%2$s,\n\
    },\n\
";

void write_fuzzer(const char *header_name, FuzgenData d, FILE *f) {
    char *constructor_fns = malloc(1000 * sizeof(char));
    char *constructor_list= malloc(1000 * sizeof(char));
    char *method_fns = malloc(1000 * sizeof(char));
    char *method_list = malloc(1000 * sizeof(char));
    constructor_fns[0] = '\0';
    constructor_list[0] = '\0';
    method_fns[0] = '\0';
    method_list[0] = '\0';

    char *args = malloc(1000 * sizeof(char));
    char *call_args = malloc(1000 * sizeof(char));

    /// CONSTRUCTORS
    for (size_t i = 0; i < d.constr_len; ++i) {
        // constructors fns
        if (d.constructors[i].arg_len == 0) {
            sprintf(
                constructor_fns + strlen(constructor_fns),
                CONSTR_FN_NOARGS,
                d.class_name,
                i
            );
        } else {
            args[0] = '\0';
            call_args[0] = '\0';

            for (size_t j = 0; j < d.constructors[i].arg_len; ++j) {
                sprintf(
                    args + strlen(args),
                    FN_ARG,
                    d.constructors[i].arg_types[j],
                    j
                );
                if (j + 1 != d.constructors[i].arg_len)
                    sprintf(
                        call_args + strlen(call_args),
                        FN_CALL_ARG,
                        j
                    );
                else
                    sprintf(
                        call_args + strlen(call_args),
                        FN_CALL_ARG_LAST,
                        j
                    );
            }

            // write
            sprintf(
                constructor_fns + strlen(constructor_fns),
                CONSTR_FN,
                d.class_name,
                i,
                args,
                call_args
            );
        }

        // call args
        args[0] = '\0';
        if (d.constructors[i].arg_len != 0) {
            for (size_t j = 0; j < d.constructors[i].arg_len - 1; ++j) {
                sprintf(
                    args + strlen(args),
                    SIZE_ARG,
                    d.constructors[i].arg_types[j]
                );
            }
            sprintf(
                args + strlen(args),
                SIZE_ARG,
                d.constructors[i].arg_types[d.constructors[i].arg_len - 1]
            );
        }

        // constructor list
        sprintf(
            constructor_list + strlen(constructor_list),
            CONSTR_LIST_ITEM,
            args,
            i
        );
    }

    /// METHODS
    for (size_t i = 0; i < d.method_len; ++i) {
        // method fns
        if (d.methods[i].arg_len == 0) {
            sprintf(
                method_fns + strlen(method_fns),
                METHOD_FN_NOARGS,
                d.methods[i].name,
                d.class_name
            );
        } else {
            args[0] = '\0';
            call_args[0] = '\0';

            for (size_t j = 0; j < d.methods[i].arg_len; ++j) {
                sprintf(
                    args + strlen(args),
                    FN_ARG,
                    d.methods[i].arg_types[j],
                    j
                );
                if (j + 1 != d.methods[i].arg_len)
                    sprintf(
                        call_args + strlen(call_args),
                        FN_CALL_ARG,
                        j
                    );
                else
                    sprintf(
                        call_args + strlen(call_args),
                        FN_CALL_ARG_LAST,
                        j
                    );
            }

            // write
            sprintf(
                method_fns + strlen(method_fns),
                METHOD_FN,
                d.methods[i].name,
                d.class_name,
                args,
                call_args
            );
        }

        // call args
        args[0] = '\0';
        if (d.methods[i].arg_len != 0) {
            for (size_t j = 0; j < d.methods[i].arg_len - 1; ++j) {
                sprintf(
                    args + strlen(args),
                    SIZE_ARG,
                    d.methods[i].arg_types[j]
                );
            }
            sprintf(
                args + strlen(args),
                SIZE_ARG,
                d.methods[i].arg_types[d.methods[i].arg_len - 1]
            );
        }

        // method list
        sprintf(
            method_list + strlen(method_list),
            METHOD_LIST_ITEM,
            args,
            d.methods[i].name
        );
    }

    fprintf(f, CORE, 
        header_name,
        d.class_name,
        constructor_fns,
        constructor_list,
        method_fns,
        method_list
    );

    free(constructor_fns);
    free(constructor_list);
    free(method_fns);
    free(method_list);
    free(args);
    free(call_args);
}

///////////////////////////// MAIN /////////////////////////////

int main(const int argc, const char **argv) {
    const FuzzerArgs args = parse_args(argc, argv);
    if (!args.header_path)
        return usage(argv[0]);

    ClangData cdata = init_clang(&args);
    if (!cdata.index)
        return print_error("Error while initializing clang");

    CXCursor class_cursor = find_class(cdata, args.class_name);
    if (clang_Cursor_isNull(class_cursor))
        return print_error("Class not found");

    FuzgenData data = from_class(args.class_name, class_cursor);
    
    FILE *file = fopen("fuzzer.cpp", "w");
    write_fuzzer(args.header_path, data, file);
    fclose(file);

    deinit(&data);
    deinit_clang(cdata);
    return 0;
}
