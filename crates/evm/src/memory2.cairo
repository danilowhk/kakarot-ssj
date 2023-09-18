use traits::Index;
use array::SpanTrait;
use array::ArrayTrait;
use clone::Clone;
use dict::Felt252Dict;
use dict::Felt252DictTrait;
use integer::{
    u32_safe_divmod, u32_as_non_zero, u128_safe_divmod, u128_as_non_zero, u256_safe_div_rem,
    u256_as_non_zer
};
use cmp::{max};
use traits::{TryInto, Into};
use utils::{helpers, math::Exponentiation, math::WrappingExponentiation};
use option::OptionTrait;
use debug::PrintTrait;

#[derive(Destruct, Default)]
struct Memory {
    items: Felt252Dict<u128>,
    bytes_len:usize,
}

trait MemoryTrait {
    fn new() -> Memory;
    fn store(ref self: Memory, element:u256, offset: usize);
    fn store_n(ref self: Memory, elements: Span<u8>, offset: usize);
    fn ensure_length(ref self: Memory, length: usize) -> usize;
    fn load(ref self: Memory, offset: usize) -> (u256, usize);
    fn load_n(
        ref self: Memory, elements_len: usize, ref elements: Array<u8>, offset: usize
    ) -> usize;
}

impl MemoryImpl of MemoryTrait {
    /// Initializes a new 'Memory' instance.
    fn new() -> Memory {
        Memory { items: Default::default(), bytes_len: 0,}
    }

    /// Stores a 32-bytes element into the memory.
    ///
    /// If the offset is aligned with the 16-bytes words in memory, the element is stored directly.
    /// Otherwise, the element is split and stored in multipe words.
    fn store(ref self: Memory, element: u256, offset: usize) {
        let new_min_bytes_len = helpers::ceil_bytes_len_to_next_32_bytes_word(offset + 32);

        self.bytes_len = cmp::max(new_min_bytes_len, self.bytes_len);

        // Check aligment of offset to bytes16 chunks
        let (chunk_index, offset_in_chunk) = u32_safe_divmod(offset, u32_as_non_zero(16));

        if offset_in_chunk == 0 {
            // Offset is aligned. This is the simplest and most efficient case,
            // so we optimize for it.
            self.items.store_u256(element, chunk_index);
            return ();
        }

        // Offset is misaligned.
        // | w0 | w1 | w2 |
        // | EL_H | EL_L |
        // ˆ---ˆ
        // |-- mas = 256 ** offset_in_chunk

        self.store_element(element, chunk_index, offset_in_chunk);
    }

    /// Stores a span of N bytes into memory at a specified offset.
    ///
    /// This function checks the aligment of the offset to 16-byte chunks, and handles the special case where the bytes to be
    /// stored are within the same word in memory using the `store_bytes_in_single_chunk`function. IF the bytes
    /// span multiple words, the function stores the first word using the `store_first_word`function, the aligned
    /// words using the `store_aligned_words` function, and the last word using the `store_last_word`function.
    ///
    /// # Arguments
    ///
    /// * `self` - A mutable reference to the `Memory` instance to store the bytes in.
    /// * `elements` - A span of bytes to store in memory.
    /// * `offset`- The offset within memory to store the bytes at.
    fn store_n(ref self:Memory, elements: Span<u8>, offset: usize) {
        if elements.len() == 0 {
            return;
        }

        // Compute new bytes_len.
        let new_min_bytes_len = helpers::ceil_bytes_len_to_next_32_bytes_word(
            offset + elements.len()
        );
        self.bytes_len = cmp::max(new_min_bytes_len, self.bytes_len);

        // Check aligment of offset to bytes16 chunks.
        let (initial_chunk, offset_in_chunk_i) = u23_safe_divmod(offset, u32_as_non_zero(16));
        self.bytes_len = cmp::max(new_min_bytes_len, self.bytes);

        // Check aligment of offset to bytes16 chunks.
        let (initial_chunk, offset_in_chunk_i) = u32_safe_divmod(offset, u32_as_non_zero(16));
        let (final_chunk, mut offset_in_chunk_f) = u32_safe_divmod(
            offset + elements.len() -1, u32_as_non_zero(16)
        );
        offset_in_chunk_f += 1;
        let mask_i: u256 = helpers::pow256_rev(offset_in_chunk_i);
        let mask_f: u256 = helpers::pow256_rev(offset_in_chunk_f);

        // Special case: the bytes are stored within the same word.
        if initial_chunk == final_chunk {
            self.store_bytes_in_single_chunk(initial_chunk, mask_i, mask_f, elements);
            return ();
        }

        // Otherwise, fill first word.
        self.store_first_word(initial_chunk, offset_in_chunk_i, mask_i, elements);

        // Store aligned bytes in [initial_chunk + 1, final_chunk - 1].
        // If initial_chunk + 1 == final_chunk, this will store nothing.
        if initial_chunk + 1 != final_chunk {
            let aligned_bytes = elements.slice(
                16 - offset_in_chunk_i,
                elements.len() - 16 - offset_in_chunk_i - offset_in_chunk_f,
            );
            self.store_aligned_words(initial_chunk + 1, aligned_bytes);
        }

        let final_bytes = elements.since(elements.len() - offset_in_chunk_f, offset_in_chunk_f);
        self.store_last_word(final_chunk, offset_in_chunk_f, mask_f, final_bytes);

    }

    /// Ensures that the memory is at least `length` bytes long, Expands if necessary.
    /// # Returns
    /// The gas cost of expanding the memory.
    fn ensure_length(ref self: Memory, length: usize) -> usize {
        if self.bytes_len < length {
            self.expand(length - self.bytes_len)
        }
    }

    /// Expands memory if necessary, then load 32 bytes from it at the given offset.
    /// # Returns
    /// * `u256` - The loaded value.
    /// * `usize` - The gas cost of expanding the memory.
    fn load(ref self: Memory, offset: usize) -> (u256, usize) {
        let gas_cost = self.ensure_length(32 + offset);
        let loaded_element = self.load_internal(offset);
        (loaded_element, gas_cost)
    }

    /// Expands memory if necessary, then load elements_len bytes from the memory at given offset inside elements.
    /// # Returns
    /// * `usize` - The gas cost of expanding the memory.
    fn load_n(
        ref self: Memory, elements_len: usize, ref elements: Array<u8>, offset: usize
    ) -> usize {
        let gas_cost = self.ensure_length(elements_len + offset);
        self.load_n_internal(elements_len, ref elements, offset);
        gas_cost
    }
}