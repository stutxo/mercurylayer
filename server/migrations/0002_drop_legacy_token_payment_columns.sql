ALTER TABLE public.tokens
    DROP COLUMN IF EXISTS invoice,
    DROP COLUMN IF EXISTS processor_id,
    DROP COLUMN IF EXISTS accepted;
