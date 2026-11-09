-- Upgrade a catalog built before ROADMAP 6 (protection by inode). Run once as the schema's owner:
--   psql -d pinakes -v ON_ERROR_STOP=1 -1 -f protected-links.sql
-- A new catalog gets the same from schema.sql; tests/test_server.py checks the two agree.

SET search_path = pinakes;

-- A file whose inode has another link under a protected root is protected at that path too: the agent says so in
-- its record; nothing readable is kept from it.
ALTER TABLE files ADD COLUMN protected_link boolean NOT NULL DEFAULT false;
CREATE OR REPLACE VIEW present WITH (security_invoker = true) AS SELECT * FROM files WHERE gone_on IS NULL;

-- What the catalog already knows: present files sharing an inode with a present file of a protected root on the
-- same host. The agents' next scans send the rest (a link the catalog never saw), as their records now differ.
UPDATE files f SET protected_link = true
FROM roots r
WHERE r.root_id = f.root_id AND NOT r.protected AND f.gone_on IS NULL AND f.nlink > 1 AND NOT f.is_symlink
  AND EXISTS (SELECT 1 FROM files p JOIN roots pr ON pr.root_id = p.root_id
              WHERE pr.protected AND pr.host_id = r.host_id AND p.dev = f.dev AND p.ino = f.ino
                AND p.gone_on IS NULL);
DELETE FROM members m USING files f
WHERE f.protected_link AND f.gone_on IS NULL AND m.archive_content_id = f.content_id;
