 // fileA.ts - Exports functions and classes
export function calculateSum(a: number, b: number): number {
    return a + b;
}

export class Calculator {
    add(a: number, b: number): number {
        return a + b;
    }
    
    multiply(a: number, b: number): number {
        return a * b;
    }
}

export const PI = 3.14159;