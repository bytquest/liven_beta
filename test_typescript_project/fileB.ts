// fileB.ts - Imports and uses entities from fileA
import { calculateSum, Calculator, PI } from './fileA';

export function processData(x: number, y: number): number {
    // This should create a cross-file relationship
    const result = calculateSum(x, y);
    return result * PI;
}

export class DataProcessor {
    private calculator: Calculator;
    
    constructor() {
        this.calculator = new Calculator();
    }
    
    process(a: number, b: number): number {
        // This should create a cross-file relationship
        return this.calculator.add(a, b);
    }
} 