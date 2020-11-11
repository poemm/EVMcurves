const path = require('path');
const fs = require('fs');

const { compiler } = require('./huff/src');
const parser = require('./huff/src/parser');

const pathToData = path.posix.resolve(__dirname, './');

const { inputMap, macros, jumptables } = parser.parseFile('main.huff', pathToData);

const {
    data: { bytecode: macroCode },
} = parser.processMacro('PAIRING', 0, [], macros, inputMap, jumptables);

console.log("0x"+macroCode)

