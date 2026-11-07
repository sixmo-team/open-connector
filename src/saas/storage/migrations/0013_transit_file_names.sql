-- Filenames are private scoped metadata, never part of the object key.
-- Historical rows have no recorded filename; readers use their actual file UUID.
ALTER TABLE integration_runtime.transit_files ADD COLUMN file_name text;
