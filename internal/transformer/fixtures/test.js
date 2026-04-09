// Test JavaScript file for minification
function add(a, b) {
    return a + b;
}

const multiply = function(x, y) {
    return x * y;
};

let result = add(5, 10);
console.log('Result:', result);

// Comments should be removed
var obj = {
    name: "test",
    value: 123,
    nested: {
        prop: true
    }
};

if (obj.value > 100) {
    console.log("Large value");
} else {
    console.log("Small value");
}

// Multiple statements
const arr = [1, 2, 3, 4, 5];
arr.forEach(item => {
    console.log(item);
});

