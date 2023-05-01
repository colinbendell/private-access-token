import { should } from 'micro-should';

import './private-access-token.test.js';
import './private-state-token.test.js';
import './utils.test.js';
console.foo = console.log;
should.run();
