// Internal imports
use kakarot::context::ExecutionContext;
use kakarot::context::ExecutionContextTrait;
use kakarot::stack::StackTrait;


#[generate_trait]
impl ComparisonAndBitwiseOperations of ComparisonAndBitwiseOperationsTrait {
    /// 0x10 - LT
    /// # Specification: https://www.evm.codes/#10?fork=shanghai
    fn exec_lt(ref self: ExecutionContext) {}

    /// 0x11 - GT
    /// # Specification: https://www.evm.codes/#11?fork=shanghai
    fn exec_gt(ref self: ExecutionContext) {}


    /// 0x12 - SLT
    /// # Specification: https://www.evm.codes/#12?fork=shanghai
    fn exec_slt(ref self: ExecutionContext) {}

    /// 0x13 - SGT
    /// # Specification: https://www.evm.codes/#13?fork=shanghai
    fn exec_sgt(ref self: ExecutionContext) {}


    /// 0x14 - EQ
    /// # Specification: https://www.evm.codes/#14?fork=shanghai
    fn exec_eq(ref self: ExecutionContext) {}

    /// 0x15 - ISZERO
    /// # Specification: https://www.evm.codes/#15?fork=shanghai
    fn exec_iszero(ref self: ExecutionContext) {}

    /// 0x16 - AND
    /// # Specification: https://www.evm.codes/#16?fork=shanghai
    fn exec_and(ref self: ExecutionContext) {
        let popped = self.stack.pop_n(2);
        let a = *popped[0];
        let b = *popped[1];
        let result = a & b;
        self.stack.push(result);
    }

    /// 0x17 - OR
    /// # Specification: https://www.evm.codes/#17?fork=shanghai
    fn exec_or(ref self: ExecutionContext) {}

    /// 0x18 - XOR operation
    /// # Specification: https://www.evm.codes/#18?fork=shanghai
    fn exec_xor(ref self: ExecutionContext) {
        let popped = self.stack.pop_n(2);
        let a = *popped[0];
        let b = *popped[1];
        let result = a ^ b;
        self.stack.push(result);
    }

    /// 0x19 - NOT
    /// Bitwise NOT operation
    /// # Specification: https://www.evm.codes/#19?fork=shanghai
    fn exec_not(ref self: ExecutionContext) {}

    /// 0x1A - BYTE
    /// # Specification: https://www.evm.codes/#1a?fork=shanghai
    fn exec_byte(ref self: ExecutionContext) {}

    /// 0x1B - SHL
    /// # Specification: https://www.evm.codes/#1b?fork=shanghai
    fn exec_shl(ref self: ExecutionContext) {}

    /// 0x1C - SHR
    /// # Specification: https://www.evm.codes/#1c?fork=shanghai
    fn exec_shr(ref self: ExecutionContext) {}

    /// 0x1D - SAR
    /// # Specification: https://www.evm.codes/#1d?fork=shanghai
    fn exec_sar(ref self: ExecutionContext) {}
}
