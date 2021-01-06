const path = require('path');
const fs = require('fs');

const { compiler, parser } = require('@aztec/huff');

const pathToData = path.posix.resolve(__dirname, './build');

const huff_file = process.argv[2];
const main_symbol = process.argv[3];

const { inputMap, macros, jumptables } = parser.parseFile(huff_file, pathToData);

const {
    data: { bytecode: macroCode },
} = parser.processMacro(main_symbol, 0, [], macros, inputMap, jumptables);
console.log(macroCode)
