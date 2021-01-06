const path = require('path');
const fs = require('fs');

const { compiler, parser } = require('@aztec/huff');

const pathToData = path.posix.resolve(__dirname, './');

const { inputMap, macros, jumptables } = parser.parseFile('main.huff', pathToData);

var arg = process.argv[2];

const {
    data: { bytecode: macroCode },
} = parser.processMacro(arg, 0, [], macros, inputMap, jumptables);
console.log(macroCode)
