import asyncio

from textual.widgets import DataTable, Input, Label

from vaultlet import vault
from vaultlet.tui import MainScreen, UnlockScreen, VaultletApp


async def unlock(app, pilot, pw):
    app.screen.query_one("#pw", Input).value = pw
    await pilot.press("enter")
    await app.workers.wait_for_complete()
    await pilot.pause()


def test_tui_flow(tmp_path):
    path = tmp_path / "vault.json"
    vault.create(path, "pw")

    async def flow():
        app = VaultletApp(path)
        async with app.run_test() as pilot:
            await unlock(app, pilot, "nope")
            assert isinstance(app.screen, UnlockScreen)
            assert "Could not unlock" in str(app.screen.query_one("#error", Label).render())

            await unlock(app, pilot, "pw")
            assert isinstance(app.screen, MainScreen)

            await pilot.press("a")
            await pilot.pause()
            app.screen.query_one("#title", Input).value = "GitHub"
            app.screen.query_one("#password", Input).value = "s3cret"
            await pilot.press("enter")
            await pilot.pause()
            assert app.screen.query_one(DataTable).row_count == 1

            await pilot.press("ctrl+l")
            await pilot.pause()
            assert isinstance(app.screen, UnlockScreen) and app.key is None and not app.entries

    asyncio.run(flow())
    _, _, entries = vault.open_vault(path, "pw")
    assert [(e["title"], e["password"]) for e in entries] == [("GitHub", "s3cret")]
